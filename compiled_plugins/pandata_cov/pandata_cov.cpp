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
#include <map>
#include <ctime>
#include <iostream>

#include "../track_proc_hc/track_proc_hc.h"
#include "../proc_map/proc_map.h"

unsigned int bb_count = 0;
proc_t *current_proc = NULL; // TODO: do we want the more complete type

using Covered = std::tuple<std::string, std::string, uint32_t>;
std::unordered_set<Covered, TupleHash> covered;
std::map<Covered, time_t> covered_time;

std::ofstream *log_file = NULL;
std::ofstream *proc_log = NULL;

// Ordered of process transitions we've seen
std::vector<std::tuple<std::string, std::string>> proc_names;

std::string current_section;

std::string most_recent_file = "";
file_mapping most_recent_file_mapping = {0, 0};

int missed = 0;

void sbe(CPUState *cpu, TranslationBlock *tb) {
  if (address_in_kernel_code_linux(tb->pc)) {
    return;
  }

  if (current_proc == NULL || current_proc->ignore) {
    return;
  }

  uint32_t bb_start = tb->pc;

  // make blocks running together the fast case
  if (bb_start >= most_recent_file_mapping.start && bb_start < most_recent_file_mapping.end) {
    uint32_t offset = bb_start - most_recent_file_mapping.start;
    auto key = std::make_tuple(current_proc->comm, most_recent_file, offset); 
    if (covered.find(key) == covered.end()) {
        std::time_t result = std::time(nullptr);
        if (result == 0){
          printf("time() is zero\n");
        }
        covered.insert(key);
        covered_time[key] = result;
    }
    return;
  }

  std::string proc_comm = current_proc->comm;
  for (auto i = current_proc->mappings.begin(); i != current_proc->mappings.end(); i++) {
    if (bb_start >= i->second.start && bb_start < i->second.end) {
      uint32_t offset = bb_start - i->second.start;
      auto key = std::make_tuple(proc_comm, i->first, offset); 
      if (covered.find(key) == covered.end()) {
        std::time_t result = std::time(nullptr);
        if (result == 0){
          printf("time() is zero\n");
        }
        covered.insert(key);
        covered_time[key] = result;
      }
      most_recent_file = i->first;
      most_recent_file_mapping = i->second;
      return;
    }
  }
  missed++;
}

std::string last_non_ignored = ""; // Maintain the last non-ignored process

void on_current_proc_change(gpointer evdata, gpointer udata) {
    std::string next = "";

    // Update the global current_proc variable
    current_proc = (proc_t*)evdata;
    most_recent_file_mapping = {0, 0};

    // Check if the current process should be ignored
    bool next_ignore = current_proc != NULL ? current_proc->ignore : true;

    // If the current process is not to be ignored, store its name
    if (current_proc != NULL && current_proc->comm != NULL && !next_ignore) {
        next = std::string(current_proc->comm);
    }

    // If we have a valid 'next' process that is not to be ignored, 
    // and we have a last non-ignored process, then record the transition
    if (!last_non_ignored.empty() && !next.empty()) {
        if (last_non_ignored != next) {
          // Don't record self-transitions
          proc_names.push_back(std::make_tuple(last_non_ignored, next));
        }
        last_non_ignored = next; // Update the last non-ignored process
    }
    else if (!next.empty()) {
        // If there is no last_non_ignored yet, but we have a non-ignored next, 
        // update last_non_ignored
        last_non_ignored = next;
    }
    // If 'next' is empty or to be ignored, we do nothing, effectively skipping it
}

extern "C" bool init_plugin(void *self) {
  panda_arg_list *args = panda_get_args("pandata_cov");
  const char *outfile = panda_parse_string(args, "outfile", NULL);

  if (!outfile) {
    printf("pandata_cov must be given an outfile argument\n");
    return false;
  }
  log_file = new std::ofstream(outfile);
  // outfile probably ends with .csv, we want to add before the .csv
  std::string proc_outfile = std::string(outfile);
  proc_outfile.insert(proc_outfile.find(".csv"), ".transitions");
  proc_log = new std::ofstream(proc_outfile);

  panda_cb pcb { .start_block_exec = sbe };
  panda_register_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb);

  PPP_REG_CB("proc_map", on_current_proc_change, on_current_proc_change);
  return true;
}

extern "C" void uninit_plugin(void *self) {
  // Write coverage info, but skip the VPN
  for (const auto& key : covered) {
    if (std::get<0>(key) != "vpn"){
      if (covered_time.find(key) == covered_time.end()){
        printf("key not found\n");
      }
      time_t found_time = covered_time[key];
      *log_file  << std::get<0>(key) << "," << std::get<1>(key) << "," << std::get<2>(key) << "," << found_time << std::endl;
    }
  }

  // Now write out the process names in the order we saw them.
  for (const auto& name : proc_names) {
      *proc_log << std::get<0>(name) << "," << std::get<1>(name) << std::endl;
  }
  bb_count = covered.size();
  printf("[pandata_cov] BB count = %d\n", bb_count);
  printf("[pandata_cov] missed = %d\n", missed);
  if (log_file) log_file->close();
}
