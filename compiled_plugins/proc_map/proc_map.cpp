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

#ifdef DEBUG_PRINT
char last_printed[16];
#endif

void debug_print_proc(const char* msg, proc_t* p) {
#ifdef DEBUG_PRINT
  if (strcpy(p->comm, last_printed) != 0) {
    printf("[proc_map] %s process '%s' pid %d\n", msg, p->comm, p->pid);
    strcpy(last_printed, p->comm);
  }
#endif
}

// If this isn't on the heap it will vanish before our plugin_exit is called. Ugh!
std::unordered_map<std::tuple<uint32_t, uint32_t>, proc_t*, hash_tuple> *proc_map = \
    new std::unordered_map<std::tuple<uint32_t, uint32_t>, proc_t*, hash_tuple>;

proc_t *current_proc = NULL;

bool should_ignore(proc_t* p)  {
  return p->ignore ||
         strncmp(p->comm, "vpn", sizeof(p->comm)) == 0 ||
          strncmp(p->comm, "tokio-runtime-w", sizeof(p->comm)) == 0;
}


/* TODO
QEMU_PLUGIN_EXPORT void* get_current_proc(void) {
  return (void*)&current_proc;
}
*/

void on_proc_change(gpointer evdata, gpointer udata) {
  // Just changed to a new process
  proc_t pending_proc = *(proc_t*)evdata;
  auto k = std::make_tuple(pending_proc.pid, pending_proc.create_time);
  if (proc_map->find(k) == proc_map->end()) {
    // Insert into proc map if we the process we're switching to isn't in there already
    g_mutex_lock(&lock);
    (*proc_map)[k] = (proc_t*)malloc(sizeof(proc_t));
    (*proc_map)[k]->pid = pending_proc.pid;
    (*proc_map)[k]->ignore = pending_proc.ignore;
    (*proc_map)[k]->ppid = pending_proc.ppid;
    (*proc_map)[k]->create_time = pending_proc.create_time;
    (*proc_map)[k]->prev_location = hash(pending_proc.comm);
    (*proc_map)[k]->vmas = new std::vector<vma_t*>;
    //(*proc_map)[k]->blocks = new std::set<bb_entry_t*, block_cmp>;
    strncpy((*proc_map)[k]->comm, pending_proc.comm, sizeof((*proc_map)[k]->comm));
    g_mutex_unlock(&lock);
#ifdef DEBUG_PRINT
    printf("[proc_map] New process %s (%d) with prev_location hash init to %x\n",
            (*proc_map)[k]->comm,
            (*proc_map)[k]->pid,
            (*proc_map)[k]->prev_location);
#endif
  }

  current_proc = (*proc_map)[k];
  if (should_ignore(current_proc)) current_proc->ignore = true;
  debug_print_proc("proc changed", current_proc);

  PPP_RUN_CB(on_current_proc_change, (gpointer)current_proc, (gpointer)1);
}

void on_proc_exec(gpointer evdata, gpointer udata) {
  // Current process just changed it's name. Update comm and ignore as necessary
  // Note ignore will automatically be set to true by track_proc_hc if it's a kernel thread
  char* new_name = (char*)evdata;
  if (current_proc != NULL) {
    strncpy(current_proc->comm, new_name, sizeof(current_proc->comm)-1); // Copy up to 64(?) chars
    if (should_ignore(current_proc)) current_proc->ignore = true;

    // Deterministically reset hash state since we're in a new program now
    current_proc->prev_location = hash(current_proc->comm);

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


extern "C" bool init_plugin(void *self) {
    // after loadvm reset map
    panda_cb pcb = { .after_loadvm = after_snapshot };
    panda_register_callback(self, PANDA_CB_GUEST_HYPERCALL, pcb);

    // On events from track_proc_hc, update our map
    PPP_REG_CB("track_proc_hc", on_hc_proc_change, on_proc_change);
    PPP_REG_CB("track_proc_hc", on_hc_proc_exec, on_proc_exec);
    PPP_REG_CB("track_proc_hc", on_hc_proc_vma_update, on_proc_vma_update);

    return true;
}

extern "C" void uninit_plugin(void *self) { }
