#ifndef TRACK_PROC_HC_H
#define TRACK_PROC_HC_H
//#include <glib.h>
//#include "panda/plugin.h"


// BEGIN_PYPANDA_NEEDS_THIS -- do not delete this comment bc pypanda
// api autogen needs it.  And don't put any compiler directives
// between this and END_PYPANDA_NEEDS_THIS except includes of other
// files in this directory that contain subsections like this one.

struct vma_t{
  uint64_t vma_start;
  uint64_t vma_end;
  char filename[64];
} vma_t;


struct proc_t {
  uint64_t pid;
  uint64_t ppid;
  uint64_t euid;
  uint64_t egid;
  uint64_t create_time;
  uint64_t parent_create_time;
  char comm[64];
  uint64_t argc;
  uint64_t envc;
  char argv[256][256];  //total bytes allowed for both argv and envp strings defined by ARG_MAX in include/uapi/linux/limits.h (131072 for linux 4.10)
  char envp[128][512];  //environment variables can be long
  bool ignore;
  //std::vector<vma_t*>* vmas;
  //uint32_t prev_location;
  //uint32_t last_bb_start;
  //uint32_t last_bb_end;
};

// END_PYPANDA_NEEDS_THIS -- do not delete this comment!

#endif