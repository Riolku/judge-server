import logging
import os
import sys

from dmoj.cptbox._cptbox import Debugger, bsd_get_proc_cwd, bsd_get_proc_fdno
from dmoj.cptbox.file_handlers import (
    FStatFileHandler,
    FileHandler,
    OpenFileHandler,
    OpenatFileHandler,
    RelativeFileHandler,
)
from dmoj.cptbox.filesystem_policies import FilesystemPolicy
from dmoj.cptbox.filesystem_syscall_kind import FilesystemSyscallKind
from dmoj.cptbox.handlers import (
    ACCESS_EACCES,
    ACCESS_EPERM,
    ALLOW,
)
from dmoj.cptbox.syscalls import *
from dmoj.utils.unicode import utf8text

log = logging.getLogger('dmoj.security')
open_write_flags = [os.O_WRONLY, os.O_RDWR, os.O_TRUNC, os.O_CREAT, os.O_EXCL]

try:
    open_write_flags.append(os.O_TMPFILE)
except AttributeError:
    # This may not exist on FreeBSD, so we ignore.
    pass


class IsolateTracer(dict):
    def __init__(self, read_fs, write_fs=None, writable=(1, 2)):
        super().__init__()
        self.read_fs_jail = self._compile_fs_jail(read_fs)
        self.write_fs_jail = self._compile_fs_jail(write_fs)

        if sys.platform.startswith('freebsd'):
            self._getcwd_pid = lambda pid: utf8text(bsd_get_proc_cwd(pid))
            self._getfd_pid = lambda pid, fd: utf8text(bsd_get_proc_fdno(pid, fd))
        else:
            self._getcwd_pid = lambda pid: os.readlink('/proc/%d/cwd' % pid)
            self._getfd_pid = lambda pid, fd: os.readlink('/proc/%d/fd/%d' % (pid, fd))

        self.update(
            {
                # Deny with report
                sys_openat: self.get_openat_handler('openat'),
                sys_open: self.get_open_handler('open'),
                sys_faccessat: self.get_relative_handler('faccessat', FilesystemSyscallKind.READ),
                sys_faccessat2: self.get_relative_handler('faccessat2', FilesystemSyscallKind.READ),
                sys_access: self.get_file_handler('access', FilesystemSyscallKind.READ),
                sys_readlink: self.get_file_handler('readlink', FilesystemSyscallKind.READ),
                sys_readlinkat: self.get_relative_handler('readlinkat', FilesystemSyscallKind.READ),
                sys_stat: self.get_file_handler('stat', FilesystemSyscallKind.READ),
                sys_stat64: self.get_file_handler('stat64', FilesystemSyscallKind.READ),
                sys_lstat: self.get_file_handler('lstat', FilesystemSyscallKind.READ),
                sys_lstat64: self.get_file_handler('lstat64', FilesystemSyscallKind.READ),
                sys_fstatat: self.get_fstat_handler('fstatat'),
                sys_statx: self.get_fstat_handler('statx'),
                sys_tgkill: self.check_kill,
                sys_kill: self.check_kill,
                sys_prctl: self.check_prctl,
                sys_read: ALLOW,
                sys_pread64: ALLOW,
                sys_write: ALLOW,
                sys_writev: ALLOW,
                sys_statfs: ALLOW,
                sys_statfs64: ALLOW,
                sys_getpgrp: ALLOW,
                sys_restart_syscall: ALLOW,
                sys_select: ALLOW,
                sys_newselect: ALLOW,
                sys_modify_ldt: ALLOW,
                sys_poll: ALLOW,
                sys_ppoll: ALLOW,
                sys_getgroups32: ALLOW,
                sys_sched_getaffinity: ALLOW,
                sys_sched_getparam: ALLOW,
                sys_sched_getscheduler: ALLOW,
                sys_sched_get_priority_min: ALLOW,
                sys_sched_get_priority_max: ALLOW,
                sys_sched_setscheduler: ALLOW,
                sys_timerfd_create: ALLOW,
                sys_timer_create: ALLOW,
                sys_timer_settime: ALLOW,
                sys_timer_delete: ALLOW,
                sys_sigprocmask: ALLOW,
                sys_rt_sigreturn: ALLOW,
                sys_sigreturn: ALLOW,
                sys_nanosleep: ALLOW,
                sys_sysinfo: ALLOW,
                sys_getrandom: ALLOW,
                sys_socket: ACCESS_EACCES,
                sys_socketcall: ACCESS_EACCES,
                sys_close: ALLOW,
                sys_dup: ALLOW,
                sys_dup2: ALLOW,
                sys_dup3: ALLOW,
                sys_fstat: ALLOW,
                sys_mmap: ALLOW,
                sys_mremap: ALLOW,
                sys_mprotect: ALLOW,
                sys_madvise: ALLOW,
                sys_munmap: ALLOW,
                sys_brk: ALLOW,
                sys_fcntl: ALLOW,
                sys_arch_prctl: ALLOW,
                sys_set_tid_address: ALLOW,
                sys_set_robust_list: ALLOW,
                sys_futex: ALLOW,
                sys_rt_sigaction: ALLOW,
                sys_rt_sigprocmask: ALLOW,
                sys_getrlimit: ALLOW,
                sys_ioctl: ALLOW,
                sys_getcwd: ALLOW,
                sys_geteuid: ALLOW,
                sys_getuid: ALLOW,
                sys_getegid: ALLOW,
                sys_getgid: ALLOW,
                sys_getdents: ALLOW,
                sys_lseek: ALLOW,
                sys_getrusage: ALLOW,
                sys_sigaltstack: ALLOW,
                sys_pipe: ALLOW,
                sys_pipe2: ALLOW,
                sys_clock_gettime: ALLOW,
                sys_clock_gettime64: ALLOW,
                sys_clock_getres: ALLOW,
                sys_gettimeofday: ALLOW,
                sys_getpid: ALLOW,
                sys_getppid: ALLOW,
                sys_sched_yield: ALLOW,
                sys_clone: ALLOW,
                sys_exit: ALLOW,
                sys_exit_group: ALLOW,
                sys_gettid: ALLOW,
                # x86 specific
                sys_mmap2: ALLOW,
                sys_fstat64: ALLOW,
                sys_set_thread_area: ALLOW,
                sys_ugetrlimit: ALLOW,
                sys_uname: ALLOW,
                sys_getuid32: ALLOW,
                sys_geteuid32: ALLOW,
                sys_getgid32: ALLOW,
                sys_getegid32: ALLOW,
                sys_llseek: ALLOW,
                sys_fcntl64: ALLOW,
                sys_time: ALLOW,
                sys_prlimit64: self.check_prlimit,
                sys_getdents64: ALLOW,
            }
        )

        # FreeBSD-specific syscalls
        if 'freebsd' in sys.platform:
            self.update(
                {
                    sys_mkdir: ACCESS_EPERM,
                    sys_break: ALLOW,
                    sys_sysarch: ALLOW,
                    sys_sysctl: ALLOW,  # TODO: More strict?
                    sys_sysctlbyname: ALLOW,  # TODO: More strict?
                    sys_issetugid: ALLOW,
                    sys_rtprio_thread: ALLOW,  # EPERMs when invalid anyway
                    sys_umtx_op: ALLOW,  # http://fxr.watson.org/fxr/source/kern/kern_umtx.c?v=FREEBSD60#L720
                    sys_getcontext: ALLOW,
                    sys_setcontext: ALLOW,
                    sys_pread: ALLOW,
                    sys_fsync: ALLOW,
                    sys_shm_open: self.get_open_handler('shm_open'),
                    sys_shm_open2: self.get_open_handler('shm_open2'),
                    sys_cpuset_getaffinity: ALLOW,
                    sys_thr_new: ALLOW,
                    sys_thr_exit: ALLOW,
                    sys_thr_kill: ALLOW,
                    sys_thr_self: ALLOW,
                    sys_sigsuspend: ALLOW,
                    sys_clock_getcpuclockid2: ALLOW,
                    sys_fstatfs: ALLOW,
                    sys_getdirentries: ALLOW,  # TODO: maybe check path?
                    sys_getdtablesize: ALLOW,
                    sys_kqueue: ALLOW,
                    sys_kevent: ALLOW,
                    sys_ktimer_create: ALLOW,
                    sys_ktimer_settime: ALLOW,
                    sys_ktimer_delete: ALLOW,
                    sys_cap_getmode: ALLOW,
                    sys_minherit: ALLOW,
                    sys_thr_set_name: ALLOW,
                    sys_sigfastblock: ALLOW,
                    sys_realpathat: self.get_relative_handler('realpathat', FilesystemSyscallKind.READ),
                }
            )

    def get_file_handler(self, syscall, syscall_kind, file_reg=0) -> FileHandler:
        return FileHandler(self, syscall, syscall_kind, file_reg=file_reg)

    def get_relative_handler(self, syscall, syscall_kind, file_reg=1, dir_reg=0) -> RelativeFileHandler:
        return RelativeFileHandler(self, syscall, syscall_kind, file_reg=file_reg, dir_reg=dir_reg)

    def get_open_handler(self, syscall, file_reg=0) -> OpenFileHandler:
        return OpenFileHandler(self, syscall, FilesystemSyscallKind.OPEN, file_reg=file_reg)

    def get_openat_handler(self, syscall, file_reg=1, dir_reg=0) -> OpenatFileHandler:
        return OpenatFileHandler(self, syscall, FilesystemSyscallKind.OPEN, file_reg=file_reg, dir_reg=dir_reg)

    def get_fstat_handler(self, syscall, file_reg=1, dir_reg=0) -> FStatFileHandler:
        return FStatFileHandler(self, syscall, FilesystemSyscallKind.FSTAT, file_reg=file_reg, dir_reg=dir_reg)

    def _compile_fs_jail(self, fs):
        return FilesystemPolicy(fs or [])

    def check_kill(self, debugger: Debugger) -> bool:
        # Allow tgkill to execute as long as the target thread group is the debugged process
        # libstdc++ seems to use this to signal itself, see <https://github.com/DMOJ/judge/issues/183>
        return True if debugger.uarg0 == debugger.pid else ACCESS_EPERM(debugger)

    def check_prlimit(self, debugger: Debugger) -> bool:
        return True if debugger.uarg0 in (0, debugger.pid) else ACCESS_EPERM(debugger)

    def check_prctl(self, debugger: Debugger) -> bool:
        PR_GET_DUMPABLE = 3
        PR_SET_NAME = 15
        PR_GET_NAME = 16
        PR_SET_THP_DISABLE = 41
        PR_SET_VMA = 0x53564D41  # Used on Android
        return debugger.arg0 in (PR_GET_DUMPABLE, PR_SET_NAME, PR_GET_NAME, PR_SET_THP_DISABLE, PR_SET_VMA)
