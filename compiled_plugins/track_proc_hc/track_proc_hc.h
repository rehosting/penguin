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

// assume contiguous regions
typedef struct {
  target_ulong start;
  target_ulong end;
} file_mapping;

typedef struct {
  uint32_t pid;
  uint32_t ppid;
  uint32_t create_time;
  uint32_t parent_create_time;
  char comm[64];
  char arg1[64]; //argv[1] or NULL
  char arg2[64]; //argv[2] or NULL
  bool ignore;
  std::map<std::string, file_mapping> mappings;

  //uint32_t prev_location;
  //uint32_t last_bb_start;
  //uint32_t last_bb_end;
} proc_t;

#endif