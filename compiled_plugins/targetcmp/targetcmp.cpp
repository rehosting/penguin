#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include <fstream>
#include <thread>
#include <atomic>
#include <iostream>
#include <sys/types.h>

#include "callstack_instr/callstack_instr.h"

extern "C" {
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

size_t target_str_len;
char *target_str;

// C++ set for storing unique string matches
std::set<std::string> matches;

void record_match(char *str) {
  std::string s(str);
  matches.insert(s);
}

// Called on every guest function call
void on_call(CPUState *cpu, target_ulong pc) {
#ifdef TARGET_ARM
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;
  target_ulong arg1 = env->regs[0];
  target_ulong arg2 = env->regs[1];
#elif defined(TARGET_MIPS)
  CPUArchState *env = (CPUArchState *)cpu->env_ptr;
  target_ulong arg1 = env->regs[4]; // reg 4 is a0
  target_ulong arg2 = env->regs[5]; // reg 5 is a1
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
#endif
}

// Plugin init
const char* output_dir;
bool init_plugin(void *self) {

  // Arguments must specify output_dir and target_str
  panda_arg_list *plugin_args = panda_get_args(PLUGIN_NAME);
  const char *output_dir = panda_parpse_string_req(plugin_args, "output_dir", "Output file to record compared values");
  target_str = strdup(panda_parse_string_req(plugin_args, "target_str", "String to match"));
  target_str_len = strlen(target_str);
  panda_free_args(plugin_args);

  // On every function call, use our callback to check an argument is the target_str, if so store the other arg
	PPP_REG_CB("callstack_instr", on_call, on_call);
	return true;
}

void uninit_plugin(void *self) {
  // Report output
  std::ofstream outfile;
  outfile.open(output_dir + std::string("/targetcmp.txt"));
  for (auto it = matches.begin(); it != matches.end(); ++it) {
    outfile << *it << std::endl;
  }
}