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
#include <iostream>
#include <fstream>

#include <set>
#include <vector>
#include <tuple>
#include <unordered_map>

#include "../track_proc_hc/track_proc_hc.h"
#include "../proc_map/proc_map.h"

unsigned int bb_count = 0;
proc_t *current_proc = NULL; // TODO: do we want the more complete type

using Covered = std::tuple<std::string, std::string, uint32_t>;
std::set<Covered> covered;


std::ofstream *log_file = NULL;

// Track coverage with after_block_exec callback
void sbe(CPUState *cpu, TranslationBlock *tb) {
  // Ignore kernel, non-zero exits (interrupted)
  if (panda_in_kernel_code_linux(cpu)) {
    return;
  }

  // If current proc is null, ignore
  if (current_proc == NULL) {
    //printf("[coverage] Process unknown - ignoring...\n");
    return;
  }

  if (current_proc->ignore) {
    // Kernel thread or vpn
    return;
  }

    uint32_t bb_start = tb->pc;

    // If we're re-executing the end of the last block in this process, skip it
    // This avoids using ABE callbacks which would be slower and require disabling tb chaining
    if (bb_start >= current_proc->last_bb_start && bb_start < current_proc->last_bb_end)
      return;

    current_proc->last_bb_start = bb_start;
    current_proc->last_bb_end = bb_start+tb->size;

    for (auto &&e : *current_proc->vmas) {
      if (bb_start >= e->vma_start && bb_start < e->vma_end) {
        // HIT! We're at a relative offset to some region we know of
        uint32_t offset = bb_start - e->vma_start;

        // Check if we've already covered this
        auto key = std::make_tuple(std::string(current_proc->comm), std::string(e->filename), offset);
        if (covered.find(key) != covered.end()) {
          return;
        }
        covered.insert(key);
        *log_file  << current_proc->comm << "," << e->filename << "," << offset << std::endl;
        //printf("[pandata_cov] hit %s + %x\n", e->filename, offset);
        bb_count++;

        break;
      }
    }
}

void on_current_proc_change(gpointer evdata, gpointer udata) {
  current_proc = (proc_t*)evdata;

  //if (current_proc == NULL || current_proc->ignore) {
  //  // TODO: disable ABE callback, otherwise enable?
  //}
}

extern "C" bool init_plugin(void *self) {
  panda_arg_list *args = panda_get_args("pandata_cov");
  const char *outfile = panda_parse_string(args, "outfile", NULL);

  if (!outfile) {
    printf("pandata_cov must be given an outfile argument");
    return false;
  }
  log_file = new std::ofstream(outfile);

  // ABE callback
  panda_cb pcb { .start_block_exec = sbe };
  panda_register_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb);

  // On proc change callback
  PPP_REG_CB("proc_map", on_current_proc_change, on_current_proc_change);
  return true;
}

extern "C" void uninit_plugin(void *self) {
  printf("[pandata_cov] BB count = %d\n", bb_count);
  if (log_file) log_file->close();
}
