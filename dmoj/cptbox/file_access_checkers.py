# Access Checkers for files, constructed after obtaining the debugger
import logging
import os
from typing import Callable

from dmoj.cptbox._cptbox import AT_FDCWD, Debugger
from dmoj.cptbox.filesystem_syscall_kind import FilesystemSyscallKind
from dmoj.cptbox.handlers import (
    ACCESS_EACCES,
    ACCESS_EFAULT,
    ACCESS_EINVAL,
    ACCESS_ENAMETOOLONG,
    ACCESS_ENOENT,
)
from dmoj.cptbox.tracer import MaxLengthExceeded

open_write_flags = [os.O_WRONLY, os.O_RDWR, os.O_TRUNC, os.O_CREAT, os.O_EXCL]
try:
    open_write_flags.append(os.O_TMPFILE)
except AttributeError:
    # This may not exist on FreeBSD, so we ignore.
    pass

security_log = logging.getLogger('dmoj.security')


class FileAccessCheck:
    def __init__(self, handler, debugger):
        self.handler = handler
        self.debugger = debugger

    def check(self) -> bool:
        try:
            if not self.full_access_check():
                security_log.debug('Denying access to %s via %s', self.normalized_path, self.handler.syscall)
                return ACCESS_EACCES(self.debugger)
            else:
                return True
        except AccessFailure as failure:
            failure.log()
            return failure.handle(self.debugger)

    def full_access_check(self) -> bool:
        self.fetch_relative_path()
        self.fetch_absolute_path()
        return self.access_check()

    def fetch_relative_path(self) -> None:
        try:
            self.rel_file = self.debugger.readstr(self.get_file_ptr())
        except MaxLengthExceeded as e:
            raise AccessFailure(ACCESS_ENAMETOOLONG, logging.WARNING, 'Overly long path: %r', e.args[0])
        except UnicodeDecodeError as e:
            raise AccessFailure(ACCESS_ENOENT, logging.WARNING, 'Invalid unicode: %r', e.object)

        # Either process called open(NULL, ...), or we failed to read the path
        # in cptbox.  Either way this call should not be allowed; if the path
        # was indeed NULL we can end the request before it gets to the kernel
        # without any downside, and if it was *not* NULL and we failed to read
        # it, then we should *definitely* stop the call here.
        if self.rel_file is None:
            raise AccessFailure(
                ACCESS_EFAULT, logging.DEBUG, 'Could not read path, or we got a null path via %s', self.handler.syscall
            )

    def fetch_absolute_path(self) -> None:
        if self.rel_file.startswith('/'):
            self.absolute_path = self.rel_file
        else:
            self.fetch_dir()
            self.absolute_path = os.path.join(self.dir, self.rel_file)

    def get_file_ptr(self) -> int:
        return getattr(self.debugger, 'uarg%d' % self.handler.file_reg)

    def fetch_dir(self) -> None:
        self.fetch_dirfd()
        self.dir = ''  # for MyPy
        try:
            if self.dirfd == AT_FDCWD:
                self.dir = self.handler.tracer._getcwd_pid(self.debugger.tid)
            else:
                self.dir = self.handler.tracer._getfd_pid(self.debugger.tid, self.dirfd)
        except UnicodeDecodeError as e:
            raise AccessFailure(
                ACCESS_EINVAL,
                logging.ERROR,
                'Unicode decoding error when opening relative to %d: %r',
                self.dirfd,
                e.object,
            )

    # if checking went as expected, but the file is denied, return False
    # that way we can differentiate between normal behaviour and errors
    def access_check(self) -> bool:
        # We want to ensure that if there are symlinks, the user must be able to access both the symlink and
        # its destination. However, we are doing path-based checks, which means we have to check these as
        # as normalized paths. normpath can normalize a path, but also changes the meaning of paths in presence of
        # symlinked directories etc. Therefore, we compare both realpath and normpath and ensure that they refer to
        # the same file, and check the accessibility of both.
        #
        # This works, except when the child process uses /proc/self, which refers to something else in this process.
        # Therefore, we "project" it by changing it to /proc/[tid] for computing the realpath and doing the samefile
        # check. However, we still keep it as /proc/self when checking access rules.
        self.projected_path = self.normalized_path = self.normalize_path(self.absolute_path)

        self.proc_dir = f'/proc/{self.debugger.tid}'
        if self.normalized_path.startswith('/proc/self'):
            # If the child uses /proc/self, have the projected file use /proc/<pid>
            self.projected_path = os.path.join(self.proc_dir, os.path.relpath(self.normalized_path, '/proc/self'))

        elif self.normalized_path.startswith(self.proc_dir):
            # If the child process uses /proc/<pid>/foo, set the normalized path to be /proc/self/foo.
            # Access rules can more easily check /proc/self.
            self.normalized_path = os.path.join('/proc/self', os.path.relpath(self.projected_path, self.proc_dir))

        self.real_path = os.path.realpath(self.projected_path)

        try:
            same = self.projected_path == self.real_path or os.path.samefile(self.projected_path, self.real_path)
        except OSError:
            raise AccessFailure(
                ACCESS_ENOENT,
                logging.DEBUG,
                'Denying access due to inability to stat: normalizes to: %s, actually: %s',
                self.normalized_path,
                self.real_path,
            )
        else:
            if not same:
                raise AccessFailure(
                    ACCESS_EACCES,
                    logging.WARNING,
                    'Denying access due to suspected symlink trickery: normalizes to: %s, actually: %s',
                    self.normalized_path,
                    self.real_path,
                )

        self.fetch_fs_jail()
        if not self.fs_jail.check(self.normalized_path):
            return False

        if self.normalized_path != self.real_path:
            if self.real_path.startswith(self.proc_dir):
                self.real_path = os.path.join('/proc/self', os.path.relpath(self.real_path, self.proc_dir))

            if not self.fs_jail.check(self.real_path):
                return False

        return True

    def normalize_path(self, path: str) -> str:
        return '/' + os.path.normpath(path).lstrip('/')

    def fetch_dirfd(self) -> None:
        self.dirfd = AT_FDCWD
        self.post_process_dirfd()

    def post_process_dirfd(self) -> None:
        self.dirfd = (self.dirfd & 0x7FFFFFFF) - (self.dirfd & 0x80000000)

    def fetch_fs_jail(self) -> None:
        if self.handler.syscall_kind == FilesystemSyscallKind.READ:
            self.fs_jail = self.handler.tracer.read_fs_jail
        else:
            assert (
                self.handler.syscall_kind == FilesystemSyscallKind.WRITE
            ), f"FileAccessCheck can't handle non-Read/Write syscall kind {self.handler.syscall_kind}"
            self.fs_jail = self.handler.tracer.write_fs_jail


class RelativeFileAccessCheck(FileAccessCheck):
    def get_dirfd(self) -> None:
        self.dirfd = getattr(self.debugger, 'uarg%d' % self.handler.dir_reg)
        self.post_process_dirfd()


class OpenFileAccessCheck(FileAccessCheck):
    def fetch_fs_jail(self) -> None:
        assert (
            self.handler.syscall_kind == FilesystemSyscallKind.OPEN
        ), 'OpenFileAccessCheck can only be used with OPEN syscall kind'

        open_flags = self.get_open_flags()
        for flag in open_write_flags:
            # Strict equality is necessary here, since e.g. O_TMPFILE has multiple bits set,
            # and O_DIRECTORY & O_TMPFILE > 0.
            if open_flags & flag == flag:
                self.fs_jail = self.handler.tracer.write_fs_jail
                return
        else:
            self.fs_jail = self.handler.tracer.read_fs_jail

    def get_open_flags(self) -> int:
        return self.debugger.uarg1


class OpenatFileAccessCheck(OpenFileAccessCheck, RelativeFileAccessCheck):
    def get_open_flags(self) -> int:
        return self.debugger.uarg2


class FStatFileAccessCheck(RelativeFileAccessCheck):
    def full_access_check(self) -> bool:
        self.fetch_relative_path()
        if self.check_empty_statat():
            return True

        self.fetch_absolute_path()
        return self.access_check()

    def check_empty_statat(self) -> bool:
        # FIXME(tbrindus): defined here because FreeBSD 13 does not
        # implement AT_EMPTY_PATH, and 14 is not yet released (but does).
        AT_EMPTY_PATH = 0x1000
        # FIXME(tbrindus): we always follow symlinks, regardless of whether
        # AT_SYMLINK_NOFOLLOW is set. This may result in us denying files
        # we otherwise wouldn't have.
        if self.rel_file == '' and self.debugger.uarg3 & AT_EMPTY_PATH:
            # If pathname is an empty string, operate on the file referred to
            # by dirfd (which may have been obtained using the open(2) O_PATH
            # flag). In this case, dirfd can refer to any type of file, not
            # just a directory, and the behavior of fstatat() is similar to
            # that of fstat(). If dirfd is AT_FDCWD, the call operates on the
            # current working directory.
            return True

        return False

    def fetch_fs_jail(self) -> None:
        assert (
            self.handler.syscall_kind == FilesystemSyscallKind.FSTAT
        ), 'FStatFileAccessCheck can only be used with FSTAT syscall kind'
        self.fs_jail = self.handler.tracer.read_fs_jail


class AccessFailure(Exception):
    def __init__(self, handler: Callable, severity, reason_format: str, *args):
        self.handler = handler
        self.severity = severity
        self.reason_format = reason_format
        self.reason_args = args

    def handle(self, debugger: Debugger) -> bool:
        return self.handler(debugger)

    def log(self):
        security_log.log(self.severity, self.reason_format, *self.reason_args)
