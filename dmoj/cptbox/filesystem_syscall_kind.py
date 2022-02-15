from enum import Enum


class FilesystemSyscallKind(Enum):
    READ = 1
    WRITE = 2
    OPEN = 3
    FSTAT = 4
