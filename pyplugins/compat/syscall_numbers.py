"""
Native system call numbers, for a kernel with no ISF
=====================================================

The syscall trap backend (compat/syscall_trap.py) learns the numbers at boot
from the kernel's syscall metadata and sys_call_table, through its ISF.  A
kernel with neither (no DWARF, no kallsyms) uses these: name, number, argument
count, as penguin's 6.13 kernels number them at boot.  Both ABIs number by
uapi (asm-generic/unistd.h for aarch64, asm/unistd_64.h for x86_64), so the
numbers hold for older kernels; a call a kernel lacks returns -ENOSYS.  The
argument count is 6 where the metadata has none.

Checked against the host's uapi headers: no number differs.
"""

TABLES = {
    "aarch64": """
        io_setup:0:2 io_destroy:1:1 io_submit:2:3 io_cancel:3:3 io_getevents:4:5 setxattr:5:5
        lsetxattr:6:5 fsetxattr:7:5 getxattr:8:4 lgetxattr:9:4 fgetxattr:10:4 listxattr:11:3
        llistxattr:12:3 flistxattr:13:3 removexattr:14:2 lremovexattr:15:2 fremovexattr:16:2
        getcwd:17:2 eventfd2:19:2 epoll_create1:20:1 epoll_ctl:21:4 epoll_pwait:22:6 dup:23:1
        dup3:24:3 fcntl:25:3 inotify_init1:26:1 inotify_add_watch:27:3 inotify_rm_watch:28:2
        ioctl:29:3 ioprio_set:30:3 ioprio_get:31:2 flock:32:2 mknodat:33:4 mkdirat:34:3
        unlinkat:35:3 symlinkat:36:3 linkat:37:5 renameat:38:4 umount:39:2 mount:40:5
        pivot_root:41:2 statfs:43:2 fstatfs:44:2 truncate:45:2 ftruncate:46:2 fallocate:47:4
        faccessat:48:3 chdir:49:1 fchdir:50:1 chroot:51:1 fchmod:52:2 fchmodat:53:3
        fchownat:54:5 fchown:55:3 openat:56:4 close:57:1 vhangup:58:0 pipe2:59:2 quotactl:60:4
        getdents64:61:3 lseek:62:3 read:63:3 write:64:3 readv:65:3 writev:66:3 pread64:67:4
        pwrite64:68:4 preadv:69:5 pwritev:70:5 sendfile64:71:4 pselect6:72:6 ppoll:73:5
        signalfd4:74:4 vmsplice:75:4 splice:76:6 tee:77:4 readlinkat:78:4 newfstatat:79:4
        newfstat:80:2 sync:81:0 fsync:82:1 fdatasync:83:1 sync_file_range:84:4
        timerfd_create:85:2 timerfd_settime:86:4 timerfd_gettime:87:2 utimensat:88:4 acct:89:6
        capget:90:2 capset:91:2 arm64_personality:92:1 exit:93:1 exit_group:94:1 waitid:95:5
        set_tid_address:96:1 unshare:97:1 futex:98:6 set_robust_list:99:2 get_robust_list:100:3
        nanosleep:101:2 getitimer:102:2 setitimer:103:3 kexec_load:104:6 init_module:105:3
        delete_module:106:2 timer_create:107:3 timer_gettime:108:2 timer_getoverrun:109:1
        timer_settime:110:4 timer_delete:111:1 clock_settime:112:2 clock_gettime:113:2
        clock_getres:114:2 clock_nanosleep:115:4 syslog:116:3 ptrace:117:4 sched_setparam:118:2
        sched_setscheduler:119:3 sched_getscheduler:120:1 sched_getparam:121:2
        sched_setaffinity:122:3 sched_getaffinity:123:3 sched_yield:124:0
        sched_get_priority_max:125:1 sched_get_priority_min:126:1 sched_rr_get_interval:127:2
        restart_syscall:128:0 kill:129:2 tkill:130:2 tgkill:131:3 sigaltstack:132:2
        rt_sigsuspend:133:2 rt_sigaction:134:4 rt_sigprocmask:135:4 rt_sigpending:136:2
        rt_sigtimedwait:137:4 rt_sigqueueinfo:138:3 rt_sigreturn:139:0 setpriority:140:3
        getpriority:141:2 reboot:142:4 setregid:143:2 setgid:144:1 setreuid:145:2 setuid:146:1
        setresuid:147:3 getresuid:148:3 setresgid:149:3 getresgid:150:3 setfsuid:151:1
        setfsgid:152:1 times:153:1 setpgid:154:2 getpgid:155:1 getsid:156:1 setsid:157:0
        getgroups:158:2 setgroups:159:2 newuname:160:1 sethostname:161:2 setdomainname:162:2
        getrlimit:163:2 setrlimit:164:2 getrusage:165:2 umask:166:1 prctl:167:5 getcpu:168:3
        gettimeofday:169:2 settimeofday:170:2 adjtimex:171:1 getpid:172:0 getppid:173:0
        getuid:174:0 geteuid:175:0 getgid:176:0 getegid:177:0 gettid:178:0 sysinfo:179:1
        mq_open:180:4 mq_unlink:181:1 mq_timedsend:182:5 mq_timedreceive:183:5 mq_notify:184:2
        mq_getsetattr:185:3 msgget:186:2 msgctl:187:3 msgrcv:188:5 msgsnd:189:4 semget:190:3
        semctl:191:4 semtimedop:192:4 semop:193:3 shmget:194:3 shmctl:195:3 shmat:196:3
        shmdt:197:1 socket:198:3 socketpair:199:4 bind:200:3 listen:201:2 accept:202:3
        connect:203:3 getsockname:204:3 getpeername:205:3 sendto:206:6 recvfrom:207:6
        setsockopt:208:5 getsockopt:209:5 shutdown:210:2 sendmsg:211:3 recvmsg:212:3
        readahead:213:3 brk:214:1 munmap:215:2 mremap:216:5 add_key:217:5 request_key:218:4
        keyctl:219:5 clone:220:5 execve:221:3 mmap:222:6 fadvise64_64:223:4 swapon:224:2
        swapoff:225:1 mprotect:226:3 msync:227:3 mlock:228:2 munlock:229:2 mlockall:230:1
        munlockall:231:0 mincore:232:3 madvise:233:3 remap_file_pages:234:5 mbind:235:6
        get_mempolicy:236:6 set_mempolicy:237:6 migrate_pages:238:6 move_pages:239:6
        rt_tgsigqueueinfo:240:4 perf_event_open:241:5 accept4:242:4 recvmmsg:243:5 wait4:260:4
        prlimit64:261:4 fanotify_init:262:6 fanotify_mark:263:6 name_to_handle_at:264:5
        open_by_handle_at:265:3 clock_adjtime:266:2 syncfs:267:1 setns:268:2 sendmmsg:269:4
        process_vm_readv:270:6 process_vm_writev:271:6 kcmp:272:5 finit_module:273:3
        sched_setattr:274:3 sched_getattr:275:4 renameat2:276:5 seccomp:277:3 getrandom:278:3
        memfd_create:279:2 bpf:280:3 execveat:281:5 userfaultfd:282:6 membarrier:283:3
        mlock2:284:3 copy_file_range:285:6 preadv2:286:6 pwritev2:287:6 pkey_mprotect:288:4
        pkey_alloc:289:2 pkey_free:290:1 statx:291:5 io_pgetevents:292:6 rseq:293:4
        kexec_file_load:294:6 pidfd_send_signal:424:4 io_uring_setup:425:2 io_uring_enter:426:6
        io_uring_register:427:4 open_tree:428:3 move_mount:429:5 fsopen:430:2 fsconfig:431:5
        fsmount:432:3 fspick:433:3 pidfd_open:434:2 clone3:435:2 close_range:436:3 openat2:437:4
        pidfd_getfd:438:3 faccessat2:439:4 process_madvise:440:5 epoll_pwait2:441:6
        mount_setattr:442:5 quotactl_fd:443:4 landlock_create_ruleset:444:6
        landlock_add_rule:445:6 landlock_restrict_self:446:6 memfd_secret:447:1
        process_mrelease:448:2 futex_waitv:449:5 set_mempolicy_home_node:450:6 cachestat:451:4
        fchmodat2:452:4 map_shadow_stack:453:6 futex_wake:454:4 futex_wait:455:6
        futex_requeue:456:4 statmount:457:4 listmount:458:4 lsm_get_self_attr:459:4
        lsm_set_self_attr:460:4 lsm_list_modules:461:3 mseal:462:3 setxattrat:463:6
        getxattrat:464:6 listxattrat:465:5 removexattrat:466:4
    """,
    "x86_64": """
        read:0:3 write:1:3 open:2:3 close:3:1 newstat:4:2 newfstat:5:2 newlstat:6:2 poll:7:3
        lseek:8:3 mmap:9:6 mprotect:10:3 munmap:11:2 brk:12:1 rt_sigaction:13:4
        rt_sigprocmask:14:4 rt_sigreturn:15:0 ioctl:16:3 pread64:17:4 pwrite64:18:4 readv:19:3
        writev:20:3 access:21:2 pipe:22:1 select:23:5 sched_yield:24:0 mremap:25:5 msync:26:3
        mincore:27:3 madvise:28:3 shmget:29:3 shmat:30:3 shmctl:31:3 dup:32:1 dup2:33:2
        pause:34:0 nanosleep:35:2 getitimer:36:2 alarm:37:1 setitimer:38:3 getpid:39:0
        sendfile64:40:4 socket:41:3 connect:42:3 accept:43:3 sendto:44:6 recvfrom:45:6
        sendmsg:46:3 recvmsg:47:3 shutdown:48:2 bind:49:3 listen:50:2 getsockname:51:3
        getpeername:52:3 socketpair:53:4 setsockopt:54:5 getsockopt:55:5 clone:56:5 fork:57:0
        vfork:58:0 execve:59:3 exit:60:1 wait4:61:4 kill:62:2 newuname:63:1 semget:64:3
        semop:65:3 semctl:66:4 shmdt:67:1 msgget:68:2 msgsnd:69:4 msgrcv:70:5 msgctl:71:3
        fcntl:72:3 flock:73:2 fsync:74:1 fdatasync:75:1 truncate:76:2 ftruncate:77:2
        getdents:78:3 getcwd:79:2 chdir:80:1 fchdir:81:1 rename:82:2 mkdir:83:2 rmdir:84:1
        creat:85:2 link:86:2 unlink:87:1 symlink:88:2 readlink:89:3 chmod:90:2 fchmod:91:2
        chown:92:3 fchown:93:3 lchown:94:3 umask:95:1 gettimeofday:96:2 getrlimit:97:2
        getrusage:98:2 sysinfo:99:1 times:100:1 ptrace:101:4 getuid:102:0 syslog:103:3
        getgid:104:0 setuid:105:1 setgid:106:1 geteuid:107:0 getegid:108:0 setpgid:109:2
        getppid:110:0 getpgrp:111:0 setsid:112:0 setreuid:113:2 setregid:114:2 getgroups:115:2
        setgroups:116:2 setresuid:117:3 getresuid:118:3 setresgid:119:3 getresgid:120:3
        getpgid:121:1 setfsuid:122:1 setfsgid:123:1 getsid:124:1 capget:125:2 capset:126:2
        rt_sigpending:127:2 rt_sigtimedwait:128:4 rt_sigqueueinfo:129:3 rt_sigsuspend:130:2
        sigaltstack:131:2 utime:132:2 mknod:133:3 personality:135:1 ustat:136:2 statfs:137:2
        fstatfs:138:2 sysfs:139:3 getpriority:140:2 setpriority:141:3 sched_setparam:142:2
        sched_getparam:143:2 sched_setscheduler:144:3 sched_getscheduler:145:1
        sched_get_priority_max:146:1 sched_get_priority_min:147:1 sched_rr_get_interval:148:2
        mlock:149:2 munlock:150:2 mlockall:151:1 munlockall:152:0 vhangup:153:0 modify_ldt:154:3
        pivot_root:155:2 prctl:157:5 arch_prctl:158:2 adjtimex:159:1 setrlimit:160:2
        chroot:161:1 sync:162:0 acct:163:6 settimeofday:164:2 mount:165:5 umount:166:2
        swapon:167:2 swapoff:168:1 reboot:169:4 sethostname:170:2 setdomainname:171:2 iopl:172:1
        ioperm:173:3 init_module:175:3 delete_module:176:2 quotactl:179:4 gettid:186:0
        readahead:187:3 setxattr:188:5 lsetxattr:189:5 fsetxattr:190:5 getxattr:191:4
        lgetxattr:192:4 fgetxattr:193:4 listxattr:194:3 llistxattr:195:3 flistxattr:196:3
        removexattr:197:2 lremovexattr:198:2 fremovexattr:199:2 tkill:200:2 time:201:1
        futex:202:6 sched_setaffinity:203:3 sched_getaffinity:204:3 io_setup:206:2
        io_destroy:207:1 io_getevents:208:5 io_submit:209:3 io_cancel:210:3 epoll_create:213:1
        remap_file_pages:216:5 getdents64:217:3 set_tid_address:218:1 restart_syscall:219:0
        semtimedop:220:4 fadvise64:221:4 timer_create:222:3 timer_settime:223:4
        timer_gettime:224:2 timer_getoverrun:225:1 timer_delete:226:1 clock_settime:227:2
        clock_gettime:228:2 clock_getres:229:2 clock_nanosleep:230:4 exit_group:231:1
        epoll_wait:232:4 epoll_ctl:233:4 tgkill:234:3 utimes:235:2 mbind:237:6
        set_mempolicy:238:6 get_mempolicy:239:6 mq_open:240:4 mq_unlink:241:1 mq_timedsend:242:5
        mq_timedreceive:243:5 mq_notify:244:2 mq_getsetattr:245:3 kexec_load:246:6 waitid:247:5
        add_key:248:5 request_key:249:4 keyctl:250:5 ioprio_set:251:3 ioprio_get:252:2
        inotify_init:253:0 inotify_add_watch:254:3 inotify_rm_watch:255:2 migrate_pages:256:6
        openat:257:4 mkdirat:258:3 mknodat:259:4 fchownat:260:5 futimesat:261:3 newfstatat:262:4
        unlinkat:263:3 renameat:264:4 linkat:265:5 symlinkat:266:3 readlinkat:267:4
        fchmodat:268:3 faccessat:269:3 pselect6:270:6 ppoll:271:5 unshare:272:1
        set_robust_list:273:2 get_robust_list:274:3 splice:275:6 tee:276:4 sync_file_range:277:4
        vmsplice:278:4 move_pages:279:6 utimensat:280:4 epoll_pwait:281:6 signalfd:282:3
        timerfd_create:283:2 eventfd:284:1 fallocate:285:4 timerfd_settime:286:4
        timerfd_gettime:287:2 accept4:288:4 signalfd4:289:4 eventfd2:290:2 epoll_create1:291:1
        dup3:292:3 pipe2:293:2 inotify_init1:294:1 preadv:295:5 pwritev:296:5
        rt_tgsigqueueinfo:297:4 perf_event_open:298:5 recvmmsg:299:5 fanotify_init:300:6
        fanotify_mark:301:6 prlimit64:302:4 name_to_handle_at:303:5 open_by_handle_at:304:3
        clock_adjtime:305:2 syncfs:306:1 sendmmsg:307:4 setns:308:2 getcpu:309:3
        process_vm_readv:310:6 process_vm_writev:311:6 kcmp:312:5 finit_module:313:3
        sched_setattr:314:3 sched_getattr:315:4 renameat2:316:5 seccomp:317:3 getrandom:318:3
        memfd_create:319:2 kexec_file_load:320:6 bpf:321:3 execveat:322:5 userfaultfd:323:6
        membarrier:324:3 mlock2:325:3 copy_file_range:326:6 preadv2:327:6 pwritev2:328:6
        pkey_mprotect:329:4 pkey_alloc:330:2 pkey_free:331:1 statx:332:5 io_pgetevents:333:6
        rseq:334:4 uretprobe:335:0 pidfd_send_signal:424:4 io_uring_setup:425:2
        io_uring_enter:426:6 io_uring_register:427:4 open_tree:428:3 move_mount:429:5
        fsopen:430:2 fsconfig:431:5 fsmount:432:3 fspick:433:3 pidfd_open:434:2 clone3:435:2
        close_range:436:3 openat2:437:4 pidfd_getfd:438:3 faccessat2:439:4 process_madvise:440:5
        epoll_pwait2:441:6 mount_setattr:442:5 quotactl_fd:443:4 landlock_create_ruleset:444:6
        landlock_add_rule:445:6 landlock_restrict_self:446:6 memfd_secret:447:1
        process_mrelease:448:2 futex_waitv:449:5 set_mempolicy_home_node:450:6 cachestat:451:4
        fchmodat2:452:4 map_shadow_stack:453:6 futex_wake:454:4 futex_wait:455:6
        futex_requeue:456:4 statmount:457:4 listmount:458:4 lsm_get_self_attr:459:4
        lsm_set_self_attr:460:4 lsm_list_modules:461:3 mseal:462:3 setxattrat:463:6
        getxattrat:464:6 listxattrat:465:5 removexattrat:466:4
    """,
}


def native_table(arch):
    """{name: (number, nargs)} for @arch's native ABI, or {}"""
    t = {}
    for item in TABLES.get(arch, "").split():
        name, num, nargs = item.split(":")
        t[name] = (int(num), int(nargs))
    return t
