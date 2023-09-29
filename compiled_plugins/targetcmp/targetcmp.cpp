#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include <fstream>
#include <thread>
#include <atomic>
#include <iostream>
#include <filesystem>
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
  CPUArchState UNUSED(*env) = (CPUArchState *)cpu->env_ptr;
#ifdef TARGET_ARM
  arg1 = env->regs[0];
  arg2 = env->regs[1];
#elif defined(TARGET_MIPS)
  arg1 = env->active_tc.gpr[4]; // reg 4 is a0
  arg2 = env->active_tc.gpr[5]; // reg 5 is a1
#elif defined(TARGET_X86_64) and !defined(TARGET_i386)
  // No 32-bit support for now to avoid dealing with stack based args
  arg1 = env->regs[7]; // RDI
  arg2 = env->regs[6]; // RSI
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

// logfile default is cwd/targetcmp.txt
std::filesystem::path logfile = std::filesystem::current_path() / "targetcmp.txt";

bool init_plugin(void *self) {
  std::unique_ptr<panda_arg_list, void(*)(panda_arg_list*)> args(
    panda_get_args("targetcmp"), panda_free_args);

  const char* logfile_arg = panda_parse_string_opt(args.get(), "output_file",
      NULL, "Output file to record compared values into");
  if (logfile_arg) logfile = std::string(logfile_arg);

  target_str = strdup(panda_parse_string_req(args.get(), "target_str", "String to match"));
  target_str_len = strlen(target_str);

  if (target_str_len <= 0) {
    printf("targetcmp error: invalid target_str argument\n");
    return false;
  }

  // On every function call, use our callback to check an argument is the target_str, if so store the other arg
#if defined(TARGET_ARM) or defined(TARGET_MIPS) or (defined(TARGET_X86_64) and !defined(TARGET_I386))
  // Create empty file - Just so we see that something's happening
  // Open file for writing, delete anything there.
  outfile.open(logfile.string(), std::ios_base::out | std::ios_base::trunc);

	PPP_REG_CB("callstack_instr", on_call, on_call);
	return true;
#endif
  printf("ERROR: Unsupported architecture for targetcmp\n");
  return false;
}

void uninit_plugin(void *self) {
  if (outfile.is_open()) {
    outfile.close();
  }
  free((void*)target_str);
}
