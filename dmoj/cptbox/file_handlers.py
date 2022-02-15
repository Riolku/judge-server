# Handlers for file-related actions, used by isolate.py
from dmoj.cptbox._cptbox import Debugger
from dmoj.cptbox.file_access_checkers import (
    FStatFileAccessCheck,
    FileAccessCheck,
    OpenFileAccessCheck,
    OpenatFileAccessCheck,
    RelativeFileAccessCheck,
)
from dmoj.cptbox.filesystem_syscall_kind import FilesystemSyscallKind


class FileHandler:
    access_check_class = FileAccessCheck

    def __init__(self, tracer, syscall, syscall_kind, file_reg=0):
        self.tracer = tracer
        self.syscall = syscall
        self.syscall_kind = syscall_kind
        self.file_reg = file_reg

    def __call__(self, debugger: Debugger) -> bool:
        return self.access_check_class(self, debugger).check()


class RelativeFileHandler(FileHandler):
    access_check_class = RelativeFileAccessCheck

    def __init__(self, *args, dir_reg=0, file_reg=1):
        super().__init__(*args, file_reg=file_reg)
        self.dir_reg = dir_reg


class OpenFileHandler(FileHandler):
    access_check_class = OpenFileAccessCheck


class OpenatFileHandler(RelativeFileHandler):
    access_check_class = OpenatFileAccessCheck


class FStatFileHandler(RelativeFileHandler):
    access_check_class = FStatFileAccessCheck


class RenameHandler:
    def __init__(self, tracer):
        self.handler1 = FileHandler(tracer, 'rename', FilesystemSyscallKind.WRITE)
        self.handler2 = FileHandler(tracer, 'rename', FilesystemSyscallKind.WRITE, file_reg=1)

    def __call__(self, debugger) -> bool:
        return self.handler1(debugger) and self.handler2(debugger)


class RenameatHandler(RenameHandler):
    def __init__(self, tracer):
        self.handler1 = RelativeFileHandler(tracer, 'renameat', FilesystemSyscallKind.WRITE)
        self.handler2 = RelativeFileHandler(tracer, 'renameat', FilesystemSyscallKind.WRITE, file_reg=3, dir_reg=2)
