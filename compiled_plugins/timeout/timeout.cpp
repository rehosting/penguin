#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include <fstream>
#include <thread>
#include <atomic>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <chrono>
#include <ctime>

std::atomic<int> bb_count(0); // Basic block count, using atomic for thread safety
int BB_MAX = 0; 
int TIMEOUT = 0;
int UNIQUE_BBS = 0;
// Global "now"
std::chrono::time_point<std::chrono::high_resolution_clock> now;

std::string log_file;

extern "C" {
	#include "panda/panda_api.h"
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

void write_log() {
	auto end = std::chrono::high_resolution_clock::now();
	// Open log_file for writing
	if (log_file.empty()) {
		return;
	}
	std::ofstream log(log_file);
	if (!log.is_open()) {
		std::cerr << "[TIMEOUT] Couldn't open log file " << log_file << std::endl;
		return;
	}

	// Now we're going to write a CSV with bb_count and execution time
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - now);

	log << "execution_time_ms,block_count" << std::endl;
	log << duration.count() << "," << bb_count << std::endl;
	log.close();
}

 void finish() {
	write_log();
	
	// XXX we don't have a good way to shutdown pypanda analyses
	// from a C plugin :(
	panda_unload_plugins();
	//panda_break_vl_loop_req = true;
	//exit(0);
	//panda_vm_quit();
	panda_finish();
 }

void sbe_bb_ctr(CPUState *cpu, TranslationBlock *tb) {
	// XXX: This is a subset of what we claim this plugin does
	// We literally just count blocks executed (non-unique)
	// so we know how much guest code was run during a given run
	bb_count++;
}

#if 0
// Shutdown after BB_MAX unique basic blocks
// We don't track uniqueness ourselves, we fall back to the
// fact that qemu tires to infrequently translate the same block
// This is probably off by a constant factor related to cache misses
void shutdown_bbt(CPUState *cpu, target_ptr_t pc) {
	bb_count++;
	if (unlikely(bb_count > BB_MAX) && !panda_break_vl_loop_req) {
		std::cout << "[TIMEOUT] Shutting down after " << bb_count << " BBs" << std::endl;
		finish();
	}
}

// Shutdown after BB_MAX non-unique basic blocks
void shutdown_sbe(CPUState *cpu, TranslationBlock *tb) {
	bb_count++;
	if (unlikely(bb_count > BB_MAX) && !panda_break_vl_loop_req) {
		std::cout << "[TIMEOUT] Shutting down after " << bb_count << " BBs" << std::endl;
		finish();
	}
}


// Shutdown after TIMEOUT
void run_timeout() {
	std::this_thread::sleep_for(std::chrono::seconds(TIMEOUT));
	std::cout << "[TIMEOUT] Shutting down after " << TIMEOUT << " seconds" << std::endl;
	finish();
}
#endif

bool init_plugin(void *self) {
	panda_cb pcb;
	panda_arg_list *args = panda_get_args("timeout");
#if 0
	BB_MAX = panda_parse_uint32(args, "bb_limit", 0);
	TIMEOUT = panda_parse_uint32(args, "time_limit", 0);
	UNIQUE_BBS = panda_parse_uint32(args, "unique_bbs", 0); // If 1, we'll only count unique BBs when deciding if it's time to shutdown
	// It's not perfect though - unique really means count of "translated" and blocks can be translated multiple times
	// Default is just all blocks executed
#endif

	log_file = panda_parse_string_opt(args, "log", "", "log file path");

 #if 0
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
#else
	// Just track BBs and write down at end
	pcb.start_block_exec = sbe_bb_ctr;
	panda_register_callback(self, PANDA_CB_START_BLOCK_EXEC, pcb);
#endif

	now = std::chrono::high_resolution_clock::now();
	return true;
}

void uninit_plugin(void *self) {
	write_log();
}
