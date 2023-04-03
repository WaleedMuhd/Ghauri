#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u32 tgid;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    int syscall_num;
};

struct events_t {
    __u32 events[256];
};


BPF_PERF_OUTPUT(events);


int trace_clone(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *child;

    child = (struct task_struct *) PT_REGS_PARM1(ctx);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = bpf_get_current_pid_tgid();
    data.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.syscall_num = __NR_clone;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int trace_execve(struct pt_regs *ctx, const char __user *filename,
                 const char __user *const __user *__argv,
                 const char __user *const __user *__envp) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = bpf_get_current_pid_tgid();
    data.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(&data.filename, sizeof(data.filename), (void *)filename);
    data.syscall_num = __NR_execve;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_memfd_create(struct pt_regs *ctx, const char __user *name, unsigned int flags) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = bpf_get_current_pid_tgid();
    data.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.syscall_num = __NR_memfd_create;
    bpf_probe_read(&data.filename, sizeof(data.filename), (void *)name);

    char trusted_process[100] = "firefox"; // Change this to the name of your trusted process
    char process_name[sizeof(data.comm)];
    bpf_probe_read(&process_name, sizeof(data.comm), &data.comm);

    if (strncmp(process_name, trusted_process, sizeof(trusted_process)) != 0) {
        // bpf_send_signal(SIGSTOP);
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_open(struct pt_regs *ctx, const char __user *filename, int flags, umode_t mode) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = bpf_get_current_pid_tgid();
    data.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.syscall_num = __NR_open;
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_mmap(struct pt_regs *ctx, void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = bpf_get_current_pid_tgid();
    data.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.syscall_num = __NR_mmap;
    // Add additional data fields here as needed

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_chmod(struct pt_regs *ctx, const char __user *filename, mode_t mode)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = bpf_get_current_pid_tgid();
    data.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.syscall_num = __NR_chmod;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


int trace_read(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = bpf_get_current_pid_tgid();
    data.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.syscall_num = __NR_read;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_wait4(struct pt_regs *ctx, pid_t pid, int *status, int options, struct rusage *ru) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = bpf_get_current_pid_tgid();
    data.tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.syscall_num = __NR_wait4;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}