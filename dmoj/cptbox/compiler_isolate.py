import struct
import sys

from dmoj.cptbox._cptbox import AT_FDCWD, Debugger
from dmoj.cptbox.file_handlers import RenameHandler, RenameatHandler
from dmoj.cptbox.filesystem_policies import ExactFile, RecursiveDir
from dmoj.cptbox.filesystem_syscall_kind import FilesystemSyscallKind
from dmoj.cptbox.handlers import ACCESS_EFAULT, ACCESS_EPERM, ALLOW
from dmoj.cptbox.isolate import IsolateTracer
from dmoj.cptbox.syscalls import *
from dmoj.cptbox.tracer import AdvancedDebugger
from dmoj.executors.base_executor import BASE_FILESYSTEM, BASE_WRITE_FILESYSTEM


UTIME_OMIT = (1 << 30) - 2


class CompilerIsolateTracer(IsolateTracer):
    def __init__(self, tmpdir, read_fs, write_fs, *args, **kwargs):
        read_fs += BASE_FILESYSTEM + [
            RecursiveDir(tmpdir),
            ExactFile('/bin/strip'),
            RecursiveDir('/usr/x86_64-linux-gnu'),
        ]
        write_fs += BASE_WRITE_FILESYSTEM + [RecursiveDir(tmpdir)]
        super().__init__(read_fs, *args, write_fs=write_fs, **kwargs)

        self.update(
            {
                # Process spawning system calls
                sys_fork: ALLOW,
                sys_vfork: ALLOW,
                sys_execve: ALLOW,
                sys_getcpu: ALLOW,
                sys_getpgid: ALLOW,
                # Directory system calls
                sys_mkdir: self.get_file_handler('mkdir', FilesystemSyscallKind.WRITE),
                sys_mkdirat: self.get_relative_handler('mkdirat', FilesystemSyscallKind.WRITE),
                sys_rmdir: self.get_file_handler('rmdir', FilesystemSyscallKind.WRITE),
                # Linking system calls
                sys_link: self.get_file_handler('link', FilesystemSyscallKind.WRITE, file_reg=1),
                sys_linkat: self.get_relative_handler('linkat', FilesystemSyscallKind.WRITE, dir_reg=2, file_reg=3),
                sys_unlink: self.get_file_handler('unlink', FilesystemSyscallKind.WRITE),
                sys_unlinkat: self.get_relative_handler('unlinkat', FilesystemSyscallKind.WRITE),
                sys_symlink: self.get_file_handler('symlink', FilesystemSyscallKind.WRITE, file_reg=1),
                # Miscellaneous other filesystem system calls
                sys_chdir: self.get_file_handler('chdir', FilesystemSyscallKind.READ),
                sys_chmod: self.get_file_handler('chmod', FilesystemSyscallKind.WRITE),
                sys_utimensat: self.do_utimensat,
                sys_umask: ALLOW,
                sys_flock: ALLOW,
                sys_fsync: ALLOW,
                sys_fadvise64: ALLOW,
                sys_fchmodat: self.get_relative_handler('fchmodat', FilesystemSyscallKind.WRITE),
                sys_fchmod: self.check_fchmod,
                sys_fallocate: ALLOW,
                sys_ftruncate: ALLOW,
                sys_rename: RenameHandler(self),
                sys_renameat: RenameatHandler(self),
                # I/O system calls
                sys_readv: ALLOW,
                sys_pwrite64: ALLOW,
                sys_sendfile: ALLOW,
                # Event loop system calls
                sys_epoll_create: ALLOW,
                sys_epoll_create1: ALLOW,
                sys_epoll_ctl: ALLOW,
                sys_epoll_wait: ALLOW,
                sys_epoll_pwait: ALLOW,
                sys_timerfd_settime: ALLOW,
                sys_eventfd2: ALLOW,
                sys_waitid: ALLOW,
                sys_wait4: ALLOW,
                # Network system calls, we don't sandbox these
                sys_socket: ALLOW,
                sys_socketpair: ALLOW,
                sys_connect: ALLOW,
                sys_setsockopt: ALLOW,
                sys_getsockname: ALLOW,
                sys_sendmmsg: ALLOW,
                sys_recvfrom: ALLOW,
                sys_sendto: ALLOW,
                # Miscellaneous other system calls
                sys_msync: ALLOW,
                sys_clock_nanosleep: ALLOW,
                sys_memfd_create: ALLOW,
                sys_rt_sigsuspend: ALLOW,
            }
        )

        # FreeBSD-specific syscalls
        if 'freebsd' in sys.platform:
            self.update(
                {
                    sys_rfork: ALLOW,
                    sys_procctl: ALLOW,
                    sys_cap_rights_limit: ALLOW,
                    sys_posix_fadvise: ALLOW,
                    sys_posix_fallocate: ALLOW,
                    sys_setrlimit: ALLOW,
                    sys_cap_ioctls_limit: ALLOW,
                    sys_cap_fcntls_limit: ALLOW,
                    sys_cap_enter: ALLOW,
                    sys_utimes: self.get_file_handler('utimes', FilesystemSyscallKind.WRITE),
                }
            )

    def do_utimensat(self, debugger: AdvancedDebugger) -> bool:
        timespec = struct.Struct({32: '=ii', 64: '=QQ'}[debugger.address_bits])

        # Emulate https://github.com/torvalds/linux/blob/v5.14/fs/utimes.c#L152-L161
        times_ptr = debugger.uarg2
        if times_ptr:
            try:
                buffer = debugger.readbytes(times_ptr, timespec.size * 2)
            except OSError:
                return ACCESS_EFAULT(debugger)

            times = list(timespec.iter_unpack(buffer))
            if times[0][1] == UTIME_OMIT and times[1][1] == UTIME_OMIT:
                debugger.syscall = -1

                def on_return():
                    debugger.result = 0

                debugger.on_return(on_return)
                return True

        # Emulate https://github.com/torvalds/linux/blob/v5.14/fs/utimes.c#L142-L143
        if debugger.uarg0 != AT_FDCWD and not debugger.uarg1:
            path = self._getfd_pid(debugger.tid, debugger.uarg0)
            return True if self.write_fs_jail.check(path) else ACCESS_EPERM(debugger)

        return self.get_relative_handler('utimensat', FilesystemSyscallKind.WRITE)(debugger)

    def check_fchmod(self, debugger: Debugger) -> bool:
        path = self._getfd_pid(debugger.tid, debugger.uarg0)
        return True if self.write_fs_jail.check(path) else ACCESS_EPERM(debugger)
