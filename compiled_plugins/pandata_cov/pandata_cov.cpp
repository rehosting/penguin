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
#include <algorithm>

#include <set>
#include <vector>
#include <tuple>
#include <unordered_set>

#include "../track_proc_hc/track_proc_hc.h"
#include "../proc_map/proc_map.h"

unsigned int bb_count = 0;
proc_t *current_proc = NULL; // TODO: do we want the more complete type

using Covered = std::tuple<std::string, std::string, uint32_t>;
std::unordered_set<Covered, TupleHash> covered;

std::ofstream *log_file = NULL;
std::ofstream *proc_log = NULL;

// Ordered of process transitions we've seen
std::vector<std::tuple<std::string, std::string>> proc_names;


void sbe(CPUState *cpu, TranslationBlock *tb) {
  if (panda_in_kernel_code_linux(cpu)) {
    return;
  }

  if (current_proc == NULL || current_proc->ignore) {
    return;
  }

  uint32_t bb_start = tb->pc;
  //if (bb_start >= current_proc->last_bb_start && bb_start < current_proc->last_bb_end)
  //  return;
  //current_proc->last_bb_start = bb_start;
  //current_proc->last_bb_end = bb_start+tb->size;

  std::string proc_comm = current_proc->comm;
  for (auto &&e : *current_proc->vmas) {
    if (bb_start >= e->vma_start && bb_start < e->vma_end) {
      uint32_t offset = bb_start - e->vma_start;
      std::string filename = e->filename;
      auto key = std::make_tuple(proc_comm, filename, offset);
      if (covered.find(key) == covered.end()) {
        covered.insert(key);
        bb_count++;
      }
      break;
    }
  }
}

void on_current_proc_change(gpointer evdata, gpointer udata) {
  std::string last = "";
  std::string next = "";

  bool last_ignore = current_proc != NULL ? current_proc->ignore : true;
  if (current_proc != NULL && current_proc->comm != NULL && !last_ignore) {
    last = std::string(current_proc->comm);
  }

  current_proc = (proc_t*)evdata;
  if (current_proc != NULL && current_proc->comm != NULL && !current_proc->ignore) {
    next = std::string(current_proc->comm);
  }

  // Record only if at least one of the processes is not ignored
  if (!last_ignore || (current_proc != NULL && !current_proc->ignore))
    proc_names.push_back(std::make_tuple(last, next));
}

extern "C" bool init_plugin(void *self) {
  panda_arg_list *args = panda_get_args("pandata_cov");
  const char *outfile = panda_parse_string(args, "outfile", NULL);

  if (!outfile) {
    printf("pandata_cov must be given an outfile argument\n");
    return false;
  }
  log_file = new std::ofstream(outfile);
  proc_log = new std::ofstream(outfile+std::string(".proc.csv"));

  panda_cb pcb { .start_block_exec = sbe };
  panda_register_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb);

  PPP_REG_CB("proc_map", on_current_proc_change, on_current_proc_change);
  return true;
}

extern "C" void uninit_plugin(void *self) {
  for (const auto& key : covered) {
    *log_file  << std::get<0>(key) << "," << std::get<1>(key) << "," << std::get<2>(key) << std::endl;
  }

  // Now write out the process names in the order we saw them. Ignore the igloo VPN though
  for (const auto& name : proc_names) {
    if (std::get<0>(name) != "vpn")
      *proc_log << std::get<0>(name) << "," << std::get<1>(name) << std::endl;
  }

  printf("[pandata_cov] BB count = %d\n", bb_count);
  if (log_file) log_file->close();
}
