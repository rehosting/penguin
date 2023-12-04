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

#include "../track_proc_hc/track_proc_hc.h"
#include "../proc_map/proc_map.h"

proc_t *current_proc = NULL; // TODO: do we want the more complete type

using Covered = std::tuple<std::string, std::string, uint32_t>;
std::unordered_set<Covered, TupleHash> covered;

// Ordered of process transitions we've seen
std::vector<std::tuple<std::string, std::string>> proc_names;

std::string current_section;

std::string most_recent_file = "";
file_mapping most_recent_file_mapping = {0, 0};

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
    covered.insert(key);
    return;
  }

  std::string proc_comm = current_proc->comm;
  for (auto i = current_proc->mappings.begin(); i != current_proc->mappings.end(); i++) {
    if (bb_start >= i->second.start && bb_start < i->second.end) {
      uint32_t offset = bb_start - i->second.start;
      auto key = std::make_tuple(proc_comm, i->first, offset); 
      covered.insert(key);
      most_recent_file = i->first;
      most_recent_file_mapping = i->second;
      return;
    }
  }
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

const char* outfile;
const char* out_transitions;

extern "C" bool init_plugin(void *self) {
  panda_arg_list *args = panda_get_args("pandata_cov");
  const char* arg_outfile = panda_parse_string(args, "outfile", NULL);

  if (!arg_outfile) {
    printf("pandata_cov must be given an outfile argument\n");
    return false;
  }
  outfile = strdup(arg_outfile);

  // outfile probably ends with .csv, we want to add before the .csv
  std::string proc_outfile = std::string(outfile);
  proc_outfile.insert(proc_outfile.find(".csv"), ".transitions");

  // copy proc_outfile into out_transitions as a char*
  out_transitions = strdup(proc_outfile.c_str());

  panda_cb pcb { .start_block_exec = sbe };
  panda_register_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb);

  PPP_REG_CB("proc_map", on_current_proc_change, on_current_proc_change);
  return true;
}

bool writeToFile(std::ofstream& file, const std::string& data) {
    while (true) {
        file << data;
        if (!file.fail()) {
            return true; // Success
        }
        if (errno != EINTR) {
            perror("Error writing to log file");
            return false; // Fail for reasons other than an interrupted system call
        }
        // If here, it was an EINTR, so clear flags and try again
        file.clear();
    }
}

extern "C" void uninit_plugin(void *self) {
  // Write coverage info, but skip the VPN
  std::ofstream log_file = std::ofstream(outfile);
  std::ofstream proc_log = std::ofstream(out_transitions);

  if (!log_file.is_open()) {
    perror("Error opening log file");
  } else {
    // First report how many values we have in covered:
    printf("Writing a total of %ld entires to coverage.log\n", covered.size());

    for (const auto& key : covered) {
      std::string data = std::get<0>(key) + "," + std::get<1>(key) + "," + std::to_string(std::get<2>(key)) + "\n";
      if (std::get<0>(key) != "vpn") {
          if (!writeToFile(log_file, data)) {
              break; // Handle the error or break the loop
          }
      }
    }
  }

  // Now write out the process names in the order we saw them.
  for (const auto& name : proc_names) {
      proc_log << std::get<0>(name) << "," << std::get<1>(name) << std::endl;
  }

  printf("[coverage] total BB count = %ld\n", covered.size());
  log_file.flush();
  log_file.close();
}