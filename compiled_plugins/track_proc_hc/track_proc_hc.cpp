#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <algorithm>    // std::find
#include <string.h>
#include <vector>
#include <tuple>
#include <set>
#include <unordered_map>
#include <byteswap.h> // bswap_32

#define __STDC_FORMAT_MACROS
#include "track_proc_hc.h"
#include "panda/plugin.h"

//#define TARGET_ARM  // XXX just for vscode highlight
#define DEBUG_PRINT

extern "C" {
  PPP_PROT_REG_CB(on_hc_proc_change);
  PPP_PROT_REG_CB(on_hc_proc_exec);
  //PPP_PROT_REG_CB(on_hc_proc_vma_update);
}

PPP_CB_BOILERPLATE(on_hc_proc_change);
PPP_CB_BOILERPLATE(on_hc_proc_exec);
//PPP_CB_BOILERPLATE(on_hc_proc_vma_update);

bool in_vma_loop = false;
proc_t pending_proc;
vma_t* pending_vma;
std::vector<vma_t*>* vmas = new std::vector<vma_t*>;

void debug_print_proc(const char* msg, proc_t* p) {
#ifdef DEBUG_PRINT
  printf("[track_proc_hc] %s process %s pid %d\n", msg, p->comm, p->pid);
#endif
}

// Track coverage with after_block_exec callback
void abe(CPUState *env, TranslationBlock *tb, uint8_t exit_code) {
  if (exit_code != 0) return;
  //printf("EBE " TARGET_FMT_lx "\n", tb->pc);
  return;
}

bool before_hypercall(CPUState *cpu) {
uint32_t num, arg = {0};
#ifdef TARGET_ARM
  CPUArchState *env = static_cast<CPUArchState *>(cpu->env_ptr);
  num = env->regs[0];
  arg = env->regs[1];
#else
  printf("Unsupported hypercall architecture\n");
  return false;
#endif

  printf("Hypercall %d: 0x%x\n", num, arg);
  switch (num) {
    /////////// PROCESS SWITCH
    case 590: // Process switch starts with reporting  name
      pending_proc = {0};

      if (panda_virtual_memory_read(cpu, arg, (uint8_t*)&pending_proc.comm, sizeof(pending_proc.comm)) == -1) {
        strncpy(pending_proc.comm, "[error]", sizeof(pending_proc.comm));
      }
      break;

    case 591: // PID (TGID edition)
      pending_proc.pid = arg;
      break;

    case 592: // PPID
      pending_proc.ppid = arg;
      break;

    case 593: // create time
      pending_proc.create_time = arg;
      break;

    case 594: { // Is/isn't kernel thread. Update proc_map & set current_pro
      pending_proc.ignore = (arg != 0);
      debug_print_proc("process switch", &pending_proc);
      PPP_RUN_CB(on_hc_proc_change, (gpointer)&pending_proc, NULL);
      break;
    }

    /////////// EXECVE
    // On execve we should make consumers "update" the current proc to be the new name
    // i.e., we were in bash but now we're in cat, same PID/TGID/create_time/etc
    case 595: // update proc name: kernel task
    case 596: // update proc name: non-kernel task
      char comm[64];
      if (panda_virtual_memory_read(cpu, arg, (uint8_t*)comm, 64) != 0) {
        printf("ERROR: unable to read process name on execve: GVA %x\n", arg);
      }
      debug_print_proc("process execve", &pending_proc);
      PPP_RUN_CB(on_hc_proc_exec, (gpointer)comm, NULL);
    break;

    /// VMA LOOP. Build up a list of VMAs
    // At end of loop when we have our list, run callback
    case 5910: // arg 1=start, 2=finishe done, and 3=finished all
      if (arg == 1 && !in_vma_loop) { // Starting
        in_vma_loop = true;
        // Delete any stale entries from the old VMA list since they're on the heap
        for (auto &e : *vmas) {
          delete e;
        }
        vmas->clear(); // Always clear VMAs for current proc on VMA update
        // XXX if someone (proc_map) tries to use VMAs while we're updating, they'll be invalid pointers!
        // to hack around this, we call the callback an extra time with an empty list
        //PPP_RUN_CB(on_hc_proc_vma_update, (gpointer)vmas, NULL);

        pending_vma = new vma_t;

      } else if (arg == 2 && in_vma_loop) {
        // Finished a VMA
        vmas->push_back(pending_vma); // Move current vma into list and allocate a new one

        // Allocate a new one
        pending_vma = new vma_t;

      } else if (arg == 3 && in_vma_loop) {
        // Finished with all VMAs. Note the last pending_vma we allocated is junk so we'll free it
        delete pending_vma;
        in_vma_loop = false;
        debug_print_proc("vma update", &pending_proc);
        //PPP_RUN_CB(on_hc_proc_vma_update, (gpointer)vmas, NULL);
        vmas->clear();

      } else {
        printf("ERROR: vma_loop_toggle %d with in_vma_loop=%d\n", arg, in_vma_loop);
      }
      break;

    case 5911: {
      if (in_vma_loop) {
        pending_vma->vma_start = (uint32_t)arg;
      }
      break;
      }

    case 5912:
      if (in_vma_loop) {
        pending_vma->vma_end = (uint32_t)arg;
      }
      break;

    case 5913: {
      if (in_vma_loop) {
        // VMA has a name, read it out
        if (panda_virtual_memory_read(cpu, arg, (uint8_t*)&pending_vma->filename, sizeof(pending_vma->filename)) == -1) {
          strncpy(pending_vma->filename, "[error]", sizeof(pending_vma->filename));
        }
      }
      break;
      }

    case 5914:
      if (in_vma_loop) {
        // VMA is special: we support 3 types
        if (arg == 1)
          strncpy(pending_vma->filename, "[heap]", sizeof(pending_vma->filename));
        else if (arg == 2)
          strncpy(pending_vma->filename, "[stack]", sizeof(pending_vma->filename));
        else if (arg == 3)
          strncpy(pending_vma->filename, "[???]", sizeof(pending_vma->filename));
      }
      break;
  }

  return true;
}

extern "C" bool init_plugin(void *self) {
  #if defined(TARGET_ARM) || defined(TARGET_MIPS)
    // ABE callback for coverage
    panda_cb pcb = { .after_block_exec = abe };
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    // Disable tb chaining for ABE
    panda_disable_tb_chaining(); // XXX could we use end_block_exec instead to avoid this?


    // Hypercall calback for proc tracking
    panda_cb pcb2 = { .guest_hypercall = before_hypercall };
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb2);


    return true;
  #else
    printf("This plugin is only supported on ARM and MIPS\n");
    return false;
  #endif
}

extern "C" void uninit_plugin(void *self) { }
