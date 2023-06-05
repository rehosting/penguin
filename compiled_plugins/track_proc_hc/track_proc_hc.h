#ifndef __TRACKPROCHC_H__
#include <glib.h>
#include "panda/plugin.h"

// We match the qemu7 qpp api with two gpointers per callback
PPP_CB_TYPEDEF(void, on_hc_proc_change, gpointer, gpointer);
PPP_CB_TYPEDEF(void, on_hc_proc_exec, gpointer, gpointer);
PPP_CB_TYPEDEF(void, on_hc_proc_vma_update, gpointer, gpointer);

typedef struct {
  uint32_t vma_start;
  uint32_t vma_end;
  char filename[64];
} vma_t;

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  uint32_t create_time;
  char comm[64];
  bool ignore;
  std::vector<vma_t*>* vmas;
  uint32_t prev_location;
  uint32_t last_bb_end;
  uint32_t last_bb_start;
} proc_t;

#endif