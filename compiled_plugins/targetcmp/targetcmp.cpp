#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include <fstream>
#include <thread>
#include <atomic>
#include <iostream>
#include <sys/types.h>
#include <set>

#include "callstack_instr/callstack_instr.h"

extern "C" {
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

size_t target_str_len;
char *target_str;
std::ofstream outfile;

// C++ set for storing unique string matches
std::set<std::string> matches;

void record_match(char *str) {
  std::string s(str);
  if (matches.find(s) == matches.end()) {
    printf("TargetCMP finds %s\n", s.c_str());
    outfile << s << std::endl;
    matches.insert(s);
  }
}

// Called on every guest function call
void on_call(CPUState *cpu, target_ulong pc) {
target_ulong arg1, arg2 = 0;
#ifdef TARGET_ARM
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;
  arg1 = env->regs[0];
  arg2 = env->regs[1];
#elif defined(TARGET_MIPS)
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;
  arg1 = env->active_tc.gpr[4]; // reg 4 is a0
  arg2 = env->active_tc.gpr[5]; // reg 5 is a1
#else
  printf("ERROR: Unsupported architecture for targetcmp\n");
  return;
#endif

  // Read strings 
  char str1[target_str_len];
  if (panda_virtual_memory_read(cpu, arg1, (uint8_t*)str1, target_str_len) != 0) {
    return;
  }

  char str2[target_str_len];
  if (panda_virtual_memory_read(cpu, arg2, (uint8_t*)str2, target_str_len) != 0) {
    return; 
  }

  // Print matched string
  if (strncmp(str1, target_str, target_str_len) == 0) {
    record_match(str2);
  } else if (strncmp(str2, target_str, target_str_len) == 0) {
    record_match(str1);
  }
}

// Plugin init
const char* output_dir;
bool init_plugin(void *self) {

  // Arguments must specify output_dir and target_str
  panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);
  output_dir = strdup(panda_parse_string_req(plugin_args, "output_dir", "Output file to record compared values"));
  target_str = strdup(panda_parse_string_req(plugin_args, "target_str", "String to match"));
  target_str_len = strlen(target_str);
  panda_free_args(plugin_args);

  //printf("TargetCmp loaded with output_dir %s and target_str %s\n", output_dir, target_str);


  // On every function call, use our callback to check an argument is the target_str, if so store the other arg
#if defined(TARGET_ARM) or defined(TARGET_MIPS)
  // Create empty file - Just so we see that something's happening
  std::string out_path = std::string(output_dir) + std::string("/targetcmp.txt");
  // Open file for writing, delete anything there.
  outfile.open(out_path, std::ios_base::out | std::ios_base::trunc);

	PPP_REG_CB("callstack_instr", on_call, on_call);
	return true;
#endif
  printf("ERROR: Unsupported architecture for targetcmp\n");
  return false;
}

void uninit_plugin(void *self) {
  // Report output - XXX doesn't run?
  printf("TargetCmp uninit runs\n");
  fflush(NULL);

  fprintf(stderr, "TargetCmp: %lu matches found\n", matches.size());
  outfile.close();

  free((void*)target_str);
  free((void*)output_dir);
}