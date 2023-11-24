// Track state of the current processes and their VMAs
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
#include <time.h>
#include <byteswap.h>
#include <netdb.h>
#include <iostream>
#include <fstream>

#include <algorithm>    // std::find
#include <string.h>
#include <vector>
#include <tuple>
#include <set>
#include <unordered_map>

#include "../track_proc_hc/track_proc_hc.h"
#include "proc_map.h"

extern "C" {
    PPP_PROT_REG_CB(on_current_proc_change);
}
PPP_CB_BOILERPLATE(on_current_proc_change);

static GMutex lock;

// DEBUG
//#define DEBUG_PRINT

#ifdef DEBUG_PRINT
char last_printed[16];
#endif

// If this isn't on the heap it will vanish before our plugin_exit is called. Ugh!
std::unordered_map<std::tuple<uint32_t, uint32_t>, proc_t*, hash_tuple> *proc_map = NULL;

proc_t *current_proc = new proc_t;

void debug_print_proc(const char* msg, proc_t* p) {
#ifdef DEBUG_PRINT
  if (p == NULL) {
      printf("[proc_map] %s process NULL\n", msg);
      return;
  }
  if (p->comm == NULL) {
      printf("[proc_map] %s comm NULL\n", msg);
      return;
  }

  if (strcmp(p->comm, last_printed) != 0) {
    printf("[proc_map] %s process '%s' pid %d\n", msg, p->comm, p->pid);
    strncpy(last_printed, p->comm, sizeof(last_printed)-1);
    last_printed[sizeof(last_printed)-1] = '\0';
  }
#endif
}

void set_ignore_flag(proc_t* p) {
  // If we already ignored it we keep it ignored, otherwise check and set if we should
  if (p->ignore) return;

  // Set ignore flag if it's a VPN process or a tokio thread - vpn is sometimes path, othertimes just name. Tokio is always name
  p->ignore = \
          strncmp(p->comm, "/igloo/utils/vpn", sizeof(p->comm)) == 0 ||
          strncmp(p->comm, "vpn", sizeof(p->comm)) == 0 ||
          strncmp(p->comm, "tokio-runtime-w", sizeof(p->comm)) == 0;
}

void on_proc_change(gpointer evdata, gpointer udata) {
  // Just changed to a new process - if we haven't seen it before we need to add it to the map
  // and we always update current_proc to the relevant map entry

  proc_t pending_proc = *(proc_t*)evdata;
  auto k = std::make_tuple(pending_proc.pid, pending_proc.create_time);

  if (proc_map->find(k) == proc_map->end()) {
    g_mutex_lock(&lock);
    (*proc_map)[k] = new proc_t({
      .pid = pending_proc.pid,
      .ppid = pending_proc.ppid,
      .create_time = pending_proc.create_time,
      .parent_create_time = pending_proc.parent_create_time,
      // .comm and .arg{1,2} gets memcpy'd below
      .ignore = pending_proc.ignore,
      .vmas = new std::vector<vma_t*>,
      //.last_bb_start = 0,
      //.last_bb_end = 0
    });

    memcpy((*proc_map)[k]->comm, pending_proc.comm, sizeof((*proc_map)[k]->comm));
    memcpy((*proc_map)[k]->arg1, pending_proc.arg1, sizeof((*proc_map)[k]->arg2));
    memcpy((*proc_map)[k]->arg2, pending_proc.arg2, sizeof((*proc_map)[k]->arg2));
    (*proc_map)[k]->comm[sizeof((*proc_map)[k]->comm) - 1] = '\0';  // Ensure null-termination
    (*proc_map)[k]->arg1[sizeof((*proc_map)[k]->arg1) - 1] = '\0';  // Ensure null-termination
    (*proc_map)[k]->arg2[sizeof((*proc_map)[k]->arg2) - 1] = '\0';  // Ensure null-termination

    g_mutex_unlock(&lock);
    
#ifdef DEBUG_PRINT
    printf("[proc_map] Added new process to map %s (%d,%d). Size is now %ld\n",
            (*proc_map)[k]->comm,
            (*proc_map)[k]->pid, 
            (*proc_map)[k]->create_time,
            proc_map->size());
  } else {
    printf("[proc_map] Process %s (%d,%d) already in map. Size is now %ld\n",
            (*proc_map)[k]->comm,
            (*proc_map)[k]->pid,
            (*proc_map)[k]->create_time,
            proc_map->size());
#endif
  }

  // By here k must be in the map so this should be safe
  current_proc = (*proc_map)[k];
  set_ignore_flag(current_proc); // Set ignore flag if necessary (kernel thread)
  //debug_print_proc("proc changed to", current_proc);
  PPP_RUN_CB(on_current_proc_change, (gpointer)current_proc, (gpointer)1);
}

void on_proc_exec(gpointer evdata, gpointer udata) {
  // Current process just changed it's name. Update comm and ignore as necessary
  // Note ignore will automatically be set to true by track_proc_hc if it's a kernel thread
  proc_t *updated = (proc_t*)evdata;
  if (current_proc != NULL) {
    strncpy(current_proc->comm, updated->comm, sizeof(current_proc->comm)); // Copy up to 64(?) chars
    strncpy(current_proc->arg1, updated->arg1, sizeof(current_proc->arg1)); // Copy up to 64(?) chars
    strncpy(current_proc->arg2, updated->arg2, sizeof(current_proc->arg2)); // Copy up to 64(?) chars
    set_ignore_flag(current_proc);

    // Deterministically reset hash state since we're in a new program now
    //current_proc->prev_location = hash(current_proc->comm);

    PPP_RUN_CB(on_current_proc_change, (gpointer)current_proc, (gpointer)2);
   
#ifdef DEBUG_PRINT
    printf("Exec'd process %s with PID %d and PPID %d\n", current_proc->comm, current_proc->pid,
           current_proc->ppid);
#endif
  }
}

void on_proc_vma_update(gpointer evdata, gpointer udata) {
  // We get a vector<vma_t*> and we need to duplicate each entry into current_proc

  current_proc->vmas->clear(); // Clear any stale VMAs (TODO do we need to free them ugh)

  for (auto &e : *(std::vector<vma_t*>*)evdata) {
    (*current_proc->vmas).push_back(e);
  }

#ifdef DEBUG_PRINT
  printf("[proc map] current_proc is %s %d\n", current_proc->comm, current_proc->pid);
  for (auto &e : *current_proc->vmas) {
    printf("[proc map]\t VMA: named %s goes from %x to %x\n", e->filename, e->vma_start, e->vma_end);
  }
#endif
}

void after_snapshot(CPUState *cpu) {
    // Clear the proc_map and VMAs (with lock?)
    g_mutex_lock(&lock);
    // Erase heap-allocated objects for each value in the map
    for (auto& k : *proc_map) {
        delete k.second->vmas;
        k.second->vmas = NULL;
        free(k.second);
    }
    proc_map->clear(); // Clear map itself
    g_mutex_unlock(&lock);

    // Clear our "current" vars
    current_proc = NULL;
    PPP_RUN_CB(on_current_proc_change, (gpointer)current_proc, (gpointer)0);
}

std::ofstream *tree_file = NULL;

extern "C" bool init_plugin(void *self) {
  panda_arg_list *args = panda_get_args("proc_map");
  const char *outfile = panda_parse_string(args, "outfile", NULL);

  if (!outfile) {
    printf("proc_map must be given an outfile argument for the tree\n");
    return false;
  }
  tree_file = new std::ofstream(outfile);
  if (tree_file == NULL) {
    printf("Couldn't open %s for writing\n", outfile);
    return false;
  }

  g_mutex_init(&lock);
  proc_map = new std::unordered_map<std::tuple<uint32_t, uint32_t>, proc_t*, hash_tuple>;

  // after loadvm reset map
  panda_cb pcb = { .after_loadvm = after_snapshot };
  panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

  current_proc = NULL;

  // On events from track_proc_hc, update our map
  PPP_REG_CB("track_proc_hc", on_hc_proc_change, on_proc_change);
  PPP_REG_CB("track_proc_hc", on_hc_proc_exec, on_proc_exec);
  PPP_REG_CB("track_proc_hc", on_hc_proc_vma_update, on_proc_vma_update);

  return true;
}

extern "C" void uninit_plugin(void *self) {
  // Dump the proc_tree to a file

  if (tree_file) {
    // Dump tree as (pid, create_time, ppid, parent_create_time, comm) csv  
    g_mutex_lock(&lock);
    for (auto& k : *proc_map) {
      // XXX we need to escape the commas in the comm field or else it breaks the csv
      // We'll just replace them with underscores for now
      std::replace(k.second->comm, k.second->comm + sizeof(k.second->comm), ',', '_');
      *tree_file  << k.second->pid << "," << k.second->create_time << "," << k.second->ppid << "," << k.second->parent_create_time << "," << k.second->comm << "," << k.second->arg1 << "," << k.second->arg2 << std::endl;
    }
    g_mutex_unlock(&lock);
    tree_file->close();
  }
}