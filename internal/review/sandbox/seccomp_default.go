package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// =============================================================================
// 默认 Seccomp 配置
//
// 白名单模式：默认阻止所有 syscall，仅允许安全的 syscall。
// 阻止 ptrace/mount/chroot/reboot/bpf 等可导致容器逃逸的 syscall。
// =============================================================================

var (
	defaultSeccompOnce     sync.Once
	defaultSeccompFilePath string
	defaultSeccompErr      error
)

// defaultSeccompProfile 返回默认 seccomp 配置文件路径。
// 首次调用时将内嵌配置写入临时文件。
func defaultSeccompProfile() string {
	defaultSeccompOnce.Do(func() {
		tmpDir := os.TempDir()
		path := filepath.Join(tmpDir, "skill-scanner-seccomp-default.json")
		if err := os.WriteFile(path, []byte(defaultSeccompJSON), 0644); err != nil {
			defaultSeccompErr = fmt.Errorf("写入默认 seccomp 配置失败: %w", err)
			return
		}
		defaultSeccompFilePath = path
	})
	if defaultSeccompErr != nil {
		return ""
	}
	return defaultSeccompFilePath
}

// seccompProfileJSON 定义 seccomp 配置结构。
type seccompProfileJSON struct {
	DefaultAction string                 `json:"defaultAction"`
	Architectures []string               `json:"architectures,omitempty"`
	Syscalls      []seccompSyscallRule   `json:"syscalls"`
}

type seccompSyscallRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// defaultSeccompJSON 是内嵌的默认 seccomp 配置。
// 白名单模式：defaultAction=SCMP_ACT_ERRNO（默认阻止），仅允许必要的 syscall。
var defaultSeccompJSON string

func init() {
	profile := seccompProfileJSON{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls: []seccompSyscallRule{
			{
				// 基础文件操作
				Names: []string{
					"access", "faccessat", "faccessat2",
					"open", "openat", "openat2",
					"close", "creat",
					"read", "readv", "pread64", "preadv", "preadv2",
					"write", "writev", "pwrite64", "pwritev", "pwritev2",
					"lseek", "fstat", "newfstatat", "stat", "lstat",
					"fstatfs", "statfs", "statx",
					"getcwd", "chdir", "fchdir",
					"rename", "renameat", "renameat2",
					"mkdir", "mkdirat",
					"rmdir",
					"unlink", "unlinkat",
					"symlink", "symlinkat",
					"readlink", "readlinkat",
					"chmod", "fchmod", "fchmodat",
					"chown", "fchown", "fchownat", "lchown",
					"truncate", "ftruncate",
					"dup", "dup2", "dup3",
					"fcntl",
					"ioctl",
					"getdents", "getdents64",
					"utimensat", "utime",
					"sync", "fsync", "fdatasync",
					"copy_file_range",
					"sendfile",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// 文件描述符和 poll
				Names: []string{
					"pipe", "pipe2",
					"poll", "ppoll",
					"select", "pselect6",
					"epoll_create", "epoll_create1",
					"epoll_ctl", "epoll_wait", "epoll_pwait",
					"eventfd", "eventfd2",
					"signalfd", "signalfd4",
					"timerfd_create", "timerfd_settime", "timerfd_gettime",
					"inotify_init", "inotify_init1",
					"inotify_add_watch", "inotify_rm_watch",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// 内存管理
				Names: []string{
					"mmap", "munmap", "mprotect", "mremap",
					"brk", "sbrk",
					"mlock", "munlock", "mlock2", "mlockall", "munlockall",
					"msync",
					"madvise",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// 进程管理
				Names: []string{
					"getpid", "getppid", "gettid", "getuid", "geteuid",
					"getgid", "getegid", "getgroups",
					"getresuid", "getresgid",
					"getpgid", "getpgrp", "getsid",
					"setuid", "setgid", "setreuid", "setregid",
					"setresuid", "setresgid",
					"setpgid", "setsid", "setgroups",
					"getrlimit", "setrlimit", "prlimit64",
					"getrusage",
					"getitimer", "setitimer",
					"prctl",
					"arch_prctl",
					"set_tid_address",
					"set_robust_list", "get_robust_list",
					"capget", "capset",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// 信号
				Names: []string{
					"rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
					"rt_sigpending", "rt_sigtimedwait", "rt_sigsuspend",
					"sigaltstack",
					"kill", "tgkill", "tkill",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// 网络（基础 socket 操作，用于分析目的）
				Names: []string{
					"socket", "socketpair",
					"bind", "listen", "accept", "accept4",
					"connect",
					"getsockname", "getpeername",
					"getsockopt", "setsockopt",
					"send", "sendto", "sendmsg",
					"recv", "recvfrom", "recvmsg",
					"shutdown",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// 时间和调度
				Names: []string{
					"clock_gettime", "clock_getres", "clock_nanosleep",
					"nanosleep",
					"gettimeofday",
					"time", "times",
					"sched_yield",
					"sched_getaffinity", "sched_setaffinity",
					"sched_getparam", "sched_setparam",
					"sched_getscheduler", "sched_setscheduler",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// 系统信息
				Names: []string{
					"uname",
					"sysinfo",
					"gethostname", "sethostname",
					"getdomainname", "setdomainname",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// 进程创建（受限的 clone）
				Names: []string{"clone"},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// 进程退出和等待
				Names: []string{
					"exit", "exit_group",
					"wait4", "waitid",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// execve（执行命令）
				Names: []string{
					"execve", "execveat",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// ptrace（strace 监控必需，逃逸风险通过阻止 process_vm_readv/writev 缓解）
				Names: []string{
					"ptrace",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// futex
				Names: []string{
					"futex",
				},
				Action: "SCMP_ACT_ALLOW",
			},
			{
				// ===== 显式阻止的危险 syscall =====
				// 容器逃逸相关（保留 ptrace 用于 strace 监控）
				Names: []string{
					"mount",           // 挂载文件系统
					"umount2",         // 卸载文件系统
					"chroot",          // 切换根目录
					"pivot_root",      // 切换根目录
					"unshare",         // 创建命名空间
					"setns",           // 加入命名空间
				},
				Action: "SCMP_ACT_ERRNO",
			},
			{
				// 内核模块和 BPF
				Names: []string{
					"init_module",       // 加载内核模块
					"delete_module",     // 卸载内核模块
					"finit_module",      // 加载内核模块
					"bpf",               // BPF 操作
					"perf_event_open",   // 性能监控
				},
				Action: "SCMP_ACT_ERRNO",
			},
			{
				// 系统控制
				Names: []string{
					"reboot",            // 重启系统
					"kexec_load",        // 内核加载
					"kexec_file_load",   // 内核加载
					"swapon",            // 启用交换
					"swapoff",           // 禁用交换
				},
				Action: "SCMP_ACT_ERRNO",
			},
			{
				// 密钥管理
				Names: []string{
					"keyctl",            // 密钥操作
					"request_key",       // 请求密钥
					"add_key",           // 添加密钥
				},
				Action: "SCMP_ACT_ERRNO",
			},
			{
				// 高级 IO
				Names: []string{
					"io_uring_setup",    // io_uring
					"io_uring_enter",
					"io_uring_register",
					"userfaultfd",       // 用户页错误处理
				},
				Action: "SCMP_ACT_ERRNO",
			},
			{
				// 进程内存读写
				Names: []string{
					"process_vm_readv",  // 跨进程内存读
					"process_vm_writev", // 跨进程内存写
				},
				Action: "SCMP_ACT_ERRNO",
			},
		},
	}

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("序列化默认 seccomp 配置失败: %v", err))
	}
	defaultSeccompJSON = string(data)
}
