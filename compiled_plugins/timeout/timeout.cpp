#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include <fstream>
#include <thread>
#include <atomic>
#include <iostream>
#include <sys/types.h>

std::atomic<int> bb_count(0); // Basic block count, using atomic for thread safety
int BB_MAX = 0; 
int TIMEOUT = 0;
int UNIQUE_BBS = 0;

extern "C" {
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

// Shutdown after BB_MAX unique basic blocks
void shutdown_bbt(CPUState *cpu, target_ptr_t pc) {
	bb_count++;
	if (unlikely(bb_count > BB_MAX) && !panda_break_vl_loop_req) {
		std::cout << "[TIMEOUT] Shutting down after " << bb_count << " BBs" << std::endl;
		panda_vm_quit();
	}
}

// Shutdown after BB_MAX non-unique basic blocks
void shutdown_sbe(CPUState *cpu, TranslationBlock *tb) {
	bb_count++;
	if (unlikely(bb_count > BB_MAX) && !panda_break_vl_loop_req) {
		std::cout << "[TIMEOUT] Shutting down after " << bb_count << " BBs" << std::endl;
		panda_vm_quit();
	}
}

// Shutdown after TIMEOUT
void run_timeout() {
	std::this_thread::sleep_for(std::chrono::seconds(TIMEOUT));
	std::cout << "[TIMEOUT] Shutting down after " << TIMEOUT << " seconds" << std::endl;
	panda_unload_plugins();
	panda_break_vl_loop_req = true;
	//exit(0);
	panda_vm_quit();
}

bool init_plugin(void *self) {
	panda_cb pcb;
	panda_arg_list *args = panda_get_args("timeout");
	BB_MAX = panda_parse_uint32(args, "bb_limit", 0);
	TIMEOUT = panda_parse_uint32(args, "time_limit", 0);
	UNIQUE_BBS = panda_parse_uint32(args, "unique_bbs", 0); // If 1, we'll only count unique BBs when deciding if it's time to shutdown
	// It's not perfect though - unique really means count of "translated" and blocks can be translated multiple times
	// Default is just all blocks executed

	if (BB_MAX != 0) {
		if (UNIQUE_BBS != 0) {
			pcb.before_block_translate = shutdown_bbt;
			panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);
		} else {
			pcb.start_block_exec = shutdown_sbe;
			panda_register_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb);
		}
	}

	if (TIMEOUT != 0) {
		std::thread timeout_thread(run_timeout);
		timeout_thread.detach();
	}

	return true;
}

void uninit_plugin(void *self) {}
