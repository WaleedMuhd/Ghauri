from bcc import BPF
from bcc.utils import printb
import ctypes

# Define a dictionary to map syscall numbers to their names
syscall_names = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    64: "semget",
    65: "semop",
    66: "semctl",
    67: "shmdt",
    68: "msgget",
    69: "msgsnd",
    70: "msgrcv",
    71: "msgctl",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    319:"memfd_create"
    # Add more syscall names here 
}

# eBPF program to intercept clone and execve syscalls


# load the eBPF program
b = BPF("/home/muhammad/Downloads/allfiles(1)/Interceptor/Ensolab_Interceptor/event_monitor_ebpf.c")

# attach the tracepoints to the eBPF program
b.attach_kprobe(event="__x64_sys_clone", fn_name="trace_clone")
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")
b.attach_kprobe(event="__x64_sys_mmap", fn_name="trace_mmap")
b.attach_kprobe(event="__x64_sys_memfd_create", fn_name="trace_memfd_create")
b.attach_kprobe(event="__x64_sys_read", fn_name="trace_read")
b.attach_kprobe(event="__x64_sys_chmod", fn_name="trace_chmod")
b.attach_kprobe(event="__x64_sys_wait4", fn_name="trace_wait4")
b.attach_kprobe(event="__x64_sys_open", fn_name="trace_open")

output_format = "{:<10} {:<10} {:<10} {:<10} {:<16} {:<16} {:<64}"
print(output_format.format("EVENT", "PID", "PPID",
      "TGID", "COMMAND", "FILENAME", "ARGS"))


# process the events
def print_event(cpu, data, size):
    event = b["events"].event(data)
    syscall_name = syscall_names.get(event.syscall_num, "unknown")
    print(output_format.format(syscall_name, event.pid, event.ppid, event.tgid, event.comm.decode(),
                               event.filename.decode(), ""))


# continuously print the output of the tracepoints
b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
