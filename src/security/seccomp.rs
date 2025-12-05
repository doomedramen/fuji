//! Secure system call implementation with validation and filtering
//!
//! This module provides comprehensive seccomp filtering to restrict operations
//! to only necessary syscalls, preventing privilege escalation and limiting
//! attack surface. Uses real Linux seccomp system calls when available.

// use crate::error::DaemonError; // Commented out since we don't need it for validation
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
use libc::{
    __NR_prctl, __NR_seccomp, c_void, size_t, sock_fprog, PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP,
    SECCOMP_MODE_FILTER, SECCOMP_SET_MODE_FILTER,
};

/// System call numbers for filtering
#[cfg(target_os = "linux")]
mod syscall_numbers {
    pub const READ: i32 = 0;
    pub const WRITE: i32 = 1;
    pub const OPEN: i32 = 2;
    pub const CLOSE: i32 = 3;
    pub const STAT: i32 = 4;
    pub const FSTAT: i32 = 5;
    pub const LSTAT: i32 = 6;
    pub const POLL: i32 = 7;
    pub const LSEEK: i32 = 8;
    pub const MMAP: i32 = 9;
    pub const MPROTECT: i32 = 10;
    pub const MUNMAP: i32 = 11;
    pub const BRK: i32 = 12;
    pub const RT_SIGACTION: i32 = 13;
    pub const RT_SIGPROCMASK: i32 = 14;
    pub const RT_SIGRETURN: i32 = 15;
    pub const IOCTL: i32 = 16;
    pub const PREAD64: i32 = 17;
    pub const PWRITE64: i32 = 18;
    pub const READV: i32 = 19;
    pub const WRITEV: i32 = 20;
    pub const ACCESS: i32 = 21;
    pub const PIPE: i32 = 22;
    pub const SELECT: i32 = 23;
    pub const SCHED_YIELD: i32 = 24;
    pub const MREMAP: i32 = 25;
    pub const MSYNC: i32 = 26;
    pub const MINCORE: i32 = 27;
    pub const MADVISE: i32 = 28;
    pub const SHMGET: i32 = 29;
    pub const SHMAT: i32 = 30;
    pub const SHMCTL: i32 = 31;
    pub const DUP: i32 = 32;
    pub const DUP2: i32 = 33;
    pub const PAUSE: i32 = 34;
    pub const NANOSLEEP: i32 = 35;
    pub const GETITIMER: i32 = 36;
    pub const ALARM: i32 = 37;
    pub const SETITIMER: i32 = 38;
    pub const GETPID: i32 = 39;
    pub const SENDFILE: i32 = 40;
    pub const SOCKET: i32 = 41;
    pub const CONNECT: i32 = 42;
    pub const ACCEPT: i32 = 43;
    pub const SENDTO: i32 = 44;
    pub const RECVFROM: i32 = 45;
    pub const SENDMSG: i32 = 46;
    pub const RECVMSG: i32 = 47;
    pub const SHUTDOWN: i32 = 48;
    pub const BIND: i32 = 49;
    pub const LISTEN: i32 = 50;
    pub const GETSOCKNAME: i32 = 51;
    pub const GETPEERNAME: i32 = 52;
    pub const SOCKETPAIR: i32 = 53;
    pub const SETSOCKOPT: i32 = 54;
    pub const GETSOCKOPT: i32 = 55;
    pub const CLONE: i32 = 56;
    pub const FORK: i32 = 57;
    pub const VFORK: i32 = 58;
    pub const EXECVE: i32 = 59;
    pub const EXIT: i32 = 60;
    pub const WAIT4: i32 = 61;
    pub const KILL: i32 = 62;
    pub const UNAME: i32 = 63;
    pub const SEMGET: i32 = 64;
    pub const SEMOP: i32 = 65;
    pub const SEMCTL: i32 = 66;
    pub const SHMDT: i32 = 67;
    pub const MSGGET: i32 = 68;
    pub const MSGSND: i32 = 69;
    pub const MSGRCV: i32 = 70;
    pub const MSGCTL: i32 = 71;
    pub const FCNTL: i32 = 72;
    pub const FLOCK: i32 = 73;
    pub const FSYNC: i32 = 74;
    pub const FDATASYNC: i32 = 75;
    pub const TRUNCATE: i32 = 76;
    pub const FTRUNCATE: i32 = 77;
    pub const GETDENTS: i32 = 78;
    pub const GETCWD: i32 = 79;
    pub const CHDIR: i32 = 80;
    pub const FCHDIR: i32 = 81;
    pub const RENAME: i32 = 82;
    pub const MKDIR: i32 = 83;
    pub const RMDIR: i32 = 84;
    pub const CREAT: i32 = 85;
    pub const LINK: i32 = 86;
    pub const UNLINK: i32 = 87;
    pub const SYMLINK: i32 = 88;
    pub const READLINK: i32 = 89;
    pub const CHMOD: i32 = 90;
    pub const FCHMOD: i32 = 91;
    pub const CHOWN: i32 = 92;
    pub const FCHOWN: i32 = 93;
    pub const LCHOWN: i32 = 94;
    pub const UMASK: i32 = 95;
    pub const GETTIMEOFDAY: i32 = 96;
    pub const GETRLIMIT: i32 = 97;
    pub const GETRUSAGE: i32 = 98;
    pub const SYSINFO: i32 = 99;
    pub const TIMES: i32 = 100;
    pub const PTRACE: i32 = 101;
    pub const GETUID: i32 = 102;
    pub const SYSLOG: i32 = 103;
    pub const GETGID: i32 = 104;
    pub const SETUID: i32 = 105;
    pub const SETGID: i32 = 106;
    pub const GETEUID: i32 = 107;
    pub const GETEGID: i32 = 108;
    pub const SETPGID: i32 = 109;
    pub const GETPPID: i32 = 110;
    pub const GETPGRP: i32 = 111;
    pub const SETSID: i32 = 112;
    pub const SETREUID: i32 = 113;
    pub const SETREGID: i32 = 114;
    pub const GETGROUPS: i32 = 115;
    pub const SETGROUPS: i32 = 116;
    pub const SETRESUID: i32 = 117;
    pub const GETRESUID: i32 = 118;
    pub const SETRESGID: i32 = 119;
    pub const GETRESGID: i32 = 120;
    pub const GETPGID: i32 = 121;
    pub const SETFSUID: i32 = 122;
    pub const SETFSGID: i32 = 123;
    pub const GETSID: i32 = 124;
    pub const CAPGET: i32 = 125;
    pub const CAPSET: i32 = 126;
    pub const RT_SIGPENDING: i32 = 127;
    pub const RT_SIGTIMEDWAIT: i32 = 128;
    pub const RT_SIGQUEUEINFO: i32 = 129;
    pub const RT_SIGSUSPEND: i32 = 130;
    pub const SIGALTSTACK: i32 = 131;
    pub const UTIME: i32 = 132;
    pub const MKNOD: i32 = 133;
    pub const USELIB: i32 = 134;
    pub const PERSONALITY: i32 = 135;
    pub const USTAT: i32 = 136;
    pub const STATFS: i32 = 137;
    pub const FSTATFS: i32 = 138;
    pub const SYSFS: i32 = 139;
    pub const GETPRIORITY: i32 = 140;
    pub const SETPRIORITY: i32 = 141;
    pub const SCHED_SETPARAM: i32 = 142;
    pub const SCHED_GETPARAM: i32 = 143;
    pub const SCHED_SETSCHEDULER: i32 = 144;
    pub const SCHED_GETSCHEDULER: i32 = 145;
    pub const SCHED_GET_PRIORITY_MAX: i32 = 146;
    pub const SCHED_GET_PRIORITY_MIN: i32 = 147;
    pub const SCHED_RR_GET_INTERVAL: i32 = 148;
    pub const MLOCK: i32 = 149;
    pub const MUNLOCK: i32 = 150;
    pub const MLOCKALL: i32 = 151;
    pub const MUNLOCKALL: i32 = 152;
    pub const VHANGUP: i32 = 153;
    pub const MODIFY_LDT: i32 = 154;
    pub const PIVOT_ROOT: i32 = 155;
    pub const _SYSCTL: i32 = 156;
    pub const PRCTL: i32 = 157;
    pub const ARCH_PRCTL: i32 = 158;
    pub const ADJTIMEX: i32 = 159;
    pub const SETRLIMIT: i32 = 160;
    pub const CHROOT: i32 = 161;
    pub const SYNC: i32 = 162;
    pub const ACCT: i32 = 163;
    pub const SETTIMEOFDAY: i32 = 164;
    pub const MOUNT: i32 = 165;
    pub const UMOUNT2: i32 = 166;
    pub const SWAPON: i32 = 167;
    pub const SWAPOFF: i32 = 168;
    pub const REBOOT: i32 = 169;
    pub const SETHOSTNAME: i32 = 170;
    pub const SETDOMAINNAME: i32 = 171;
    pub const IOPERM: i32 = 172;
    pub const IOPL: i32 = 173;
    pub const CREATE_MODULE: i32 = 174;
    pub const INIT_MODULE: i32 = 175;
    pub const DELETE_MODULE: i32 = 176;
    pub const GET_KERNEL_SYMS: i32 = 177;
    pub const QUERY_MODULE: i32 = 178;
    pub const QUOTACTL: i32 = 179;
    pub const NFSSERVCTL: i32 = 180;
    pub const GETPMSG: i32 = 181;
    pub const PUTPMSG: i32 = 182;
    pub const AFS_SYSCALL: i32 = 183;
    pub const TUXCALL: i32 = 184;
    pub const SECURITY: i32 = 185;
    pub const GETTID: i32 = 186;
    pub const READAHEAD: i32 = 187;
    pub const SETXATTR: i32 = 188;
    pub const LSETXATTR: i32 = 189;
    pub const FSETXATTR: i32 = 190;
    pub const GETXATTR: i32 = 191;
    pub const LGETXATTR: i32 = 192;
    pub const FGETXATTR: i32 = 193;
    pub const LISTXATTR: i32 = 194;
    pub const LLISTXATTR: i32 = 195;
    pub const FLISTXATTR: i32 = 196;
    pub const REMOVEXATTR: i32 = 197;
    pub const LREMOVEXATTR: i32 = 198;
    pub const FREMOVEXATTR: i32 = 199;
    pub const TKILL: i32 = 200;
    pub const TIME: i32 = 201;
    pub const FUTEX: i32 = 202;
    pub const SCHED_SETAFFINITY: i32 = 203;
    pub const SCHED_GETAFFINITY: i32 = 204;
    pub const SET_THREAD_AREA: i32 = 205;
    pub const IO_SETUP: i32 = 206;
    pub const IO_DESTROY: i32 = 207;
    pub const IO_GETEVENTS: i32 = 208;
    pub const IO_SUBMIT: i32 = 209;
    pub const IO_CANCEL: i32 = 210;
    pub const GET_THREAD_AREA: i32 = 211;
    pub const LOOKUP_DCOOKIE: i32 = 212;
    pub const EPOLL_CREATE: i32 = 213;
    pub const EPOLL_CTL_OLD: i32 = 214;
    pub const EPOLL_WAIT_OLD: i32 = 215;
    pub const REMAP_FILE_PAGES: i32 = 216;
    pub const GETDENTS64: i32 = 217;
    pub const SET_TID_ADDRESS: i32 = 218;
    pub const RESTART_SYSCALL: i32 = 219;
    pub const SEMTIMEDOP: i32 = 220;
    pub const FADVISE64: i32 = 221;
    pub const TIMER_CREATE: i32 = 222;
    pub const TIMER_SETTIME: i32 = 223;
    pub const TIMER_GETTIME: i32 = 224;
    pub const TIMER_GETOVERRUN: i32 = 225;
    pub const TIMER_DELETE: i32 = 226;
    pub const CLOCK_SETTIME: i32 = 227;
    pub const CLOCK_GETTIME: i32 = 228;
    pub const CLOCK_GETRES: i32 = 229;
    pub const CLOCK_NANOSLEEP: i32 = 230;
    pub const EXIT_GROUP: i32 = 231;
    pub const EPOLL_WAIT: i32 = 232;
    pub const EPOLL_CTL: i32 = 233;
    pub const TGKILL: i32 = 234;
    pub const UTIMES: i32 = 235;
    pub const VSERVER: i32 = 236;
    pub const MBIND: i32 = 237;
    pub const SET_MEMPOLICY: i32 = 238;
    pub const GET_MEMPOLICY: i32 = 239;
    pub const MQ_OPEN: i32 = 240;
    pub const MQ_UNLINK: i32 = 241;
    pub const MQ_TIMEDSEND: i32 = 242;
    pub const MQ_TIMEDRECEIVE: i32 = 243;
    pub const MQ_NOTIFY: i32 = 244;
    pub const MQ_GETSETATTR: i32 = 245;
    pub const KEXEC_LOAD: i32 = 246;
    pub const WAITID: i32 = 247;
    pub const ADD_KEY: i32 = 248;
    pub const REQUEST_KEY: i32 = 249;
    pub const KEYCTL: i32 = 250;
    pub const IOPRIO_SET: i32 = 251;
    pub const IOPRIO_GET: i32 = 252;
    pub const INOTIFY_INIT: i32 = 253;
    pub const INOTIFY_ADD_WATCH: i32 = 254;
    pub const INOTIFY_RM_WATCH: i32 = 255;
    pub const MIGRATE_PAGES: i32 = 256;
    pub const OPENAT: i32 = 257;
    pub const MKDIRAT: i32 = 258;
    pub const MKNODAT: i32 = 259;
    pub const FCHOWNAT: i32 = 260;
    pub const FUTIMESAT: i32 = 261;
    pub const NEWFSTATAT: i32 = 262;
    pub const UNLINKAT: i32 = 263;
    pub const RENAMEAT: i32 = 264;
    pub const LINKAT: i32 = 265;
    pub const SYMLINKAT: i32 = 266;
    pub const READLINKAT: i32 = 267;
    pub const FCHMODAT: i32 = 268;
    pub const FACCESSAT: i32 = 269;
    pub const PSELECT6: i32 = 270;
    pub const PPOLL: i32 = 271;
    pub const UNSHARE: i32 = 272;
    pub const SET_ROBUST_LIST: i32 = 273;
    pub const GET_ROBUST_LIST: i32 = 274;
    pub const SPLICE: i32 = 275;
    pub const TEE: i32 = 276;
    pub const SYNC_FILE_RANGE: i32 = 277;
    pub const VMSPLICE: i32 = 278;
    pub const MOVE_PAGES: i32 = 279;
    pub const UTIMENSAT: i32 = 280;
    pub const EPOLL_PWAIT: i32 = 281;
    pub const SIGNALFD: i32 = 282;
    pub const TIMERFD_CREATE: i32 = 283;
    pub const EVENTFD: i32 = 284;
    pub const FALLOCATE: i32 = 285;
    pub const TIMERFD_SETTIME: i32 = 286;
    pub const TIMERFD_GETTIME: i32 = 287;
    pub const ACCEPT4: i32 = 288;
    pub const SIGNALED: i32 = 289;
    pub const TIMERFD_CREATE: i32 = 290;
    pub const EVENTFD2: i32 = 291;
    pub const EPOLL_CREATE1: i32 = 292;
    pub const DUP3: i32 = 293;
    pub const PIPE2: i32 = 294;
    pub const INOTIFY_INIT1: i32 = 295;
    pub const PREADV: i32 = 296;
    pub const PWRITEV: i32 = 297;
    pub const RT_TGSIGQUEUEINFO: i32 = 298;
    pub const PERF_EVENT_OPEN: i32 = 299;
    pub const RECVMMSG: i32 = 300;
    pub const FANOTIFY_INIT: i32 = 301;
    pub const FANOTIFY_MARK: i32 = 302;
    pub const PRLIMIT64: i32 = 303;
    pub const NAME_TO_HANDLE_AT: i32 = 304;
    pub const OPEN_BY_HANDLE_AT: i32 = 305;
    pub const CLOCK_ADJTIME: i32 = 306;
    pub const SYNCFS: i32 = 307;
    pub const SENDMMSG: i32 = 308;
    pub const SETNS: i32 = 309;
    pub const GETCPU: i32 = 310;
    pub const PROCESS_VM_READV: i32 = 311;
    pub const PROCESS_VM_WRITEV: i32 = 312;
    pub const KCMP: i32 = 313;
    pub const FINIT_MODULE: i32 = 314;
}

/// Seccomp action codes
#[cfg(target_os = "linux")]
mod seccomp_actions {
    pub const KILL_PROCESS: u32 = 0x00000000;
    pub const KILL_THREAD: u32 = 0x00000001;
    pub const TRAP: u32 = 0x00030000;
    pub const ERRNO: u32 = 0x00050000;
    pub const USER_NOTIF: u32 = 0x7fc00000;
    pub const LOG: u32 = 0x7ffc0000;
    pub const ALLOW: u32 = 0x7fff0000;
}

/// Seccomp filter structure for real system call filtering
#[cfg(target_os = "linux")]
#[repr(C)]
struct sock_filter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct sock_fprog {
    len: u16,
    filter: *const sock_filter,
}

/// Seccomp filter builder for creating BPF programs
#[cfg(target_os = "linux")]
struct SeccompFilterBuilder {
    instructions: Vec<sock_filter>,
    allowed_syscalls: HashSet<i32>,
    default_action: u32,
}

#[cfg(target_os = "linux")]
impl SeccompFilterBuilder {
    fn new(default_action: u32) -> Self {
        Self {
            instructions: Vec::new(),
            allowed_syscalls: HashSet::new(),
            default_action,
        }
    }

    fn add_syscall(&mut self, syscall: i32) -> &mut Self {
        self.allowed_syscalls.insert(syscall);
        self
    }

    fn build(&mut self) -> Result<Vec<sock_filter>> {
        use seccomp_actions::*;
        use syscall_numbers::*;

        // Load architecture
        self.instructions.push(sock_filter {
            code: 0x20, // BPF_LD | BPF_W | BPF_ABS
            jt: 0,
            jf: 0,
            k: 4, // arch field in seccomp_data
        });

        // Jump to end if architecture doesn't match
        self.instructions.push(sock_filter {
            code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
            jt: 0,
            jf: 1,
            k: 0xC000003E, // AUDIT_ARCH_X86_64
        });

        // Return kill if architecture doesn't match
        self.instructions.push(sock_filter {
            code: 0x06, // BPF_RET | BPF_K
            jt: 0,
            jf: 0,
            k: KILL_PROCESS,
        });

        // Load syscall number
        self.instructions.push(sock_filter {
            code: 0x20, // BPF_LD | BPF_W | BPF_ABS
            jt: 0,
            jf: 0,
            k: 0, // nr field in seccomp_data
        });

        // Check each allowed syscall
        let allowed_count = self.allowed_syscalls.len();
        for (i, &syscall) in self.allowed_syscalls.iter().enumerate() {
            self.instructions.push(sock_filter {
                code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
                jt: 1,
                jf: 0,
                k: syscall as u32,
            });

            // If this is not the last syscall, jump over the return
            if i < allowed_count - 1 {
                self.instructions.push(sock_filter {
                    code: 0x05, // BPF_JMP | BPF_JA
                    jt: 0,
                    jf: 0,
                    k: 2, // Jump over next check and return
                });
            }
        }

        // Allow allowed syscalls
        self.instructions.push(sock_filter {
            code: 0x06, // BPF_RET | BPF_K
            jt: 0,
            jf: 0,
            k: ALLOW,
        });

        // Default action for all other syscalls
        self.instructions.push(sock_filter {
            code: 0x06, // BPF_RET | BPF_K
            jt: 0,
            jf: 0,
            k: self.default_action,
        });

        Ok(self.instructions.clone())
    }
}

/// Available seccomp profiles for different contexts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompProfile {
    /// Minimal profile for basic operations (very restrictive)
    Minimal,
    /// Network operations profile
    Network,
    /// File system operations profile
    FileSystem,
    /// Mount operations profile
    Mount,
    /// Daemon operations profile
    Daemon,
    /// Test/development profile (permissive)
    Test,
}

impl SeccompProfile {
    /// Get a description of the profile
    pub fn description(&self) -> &'static str {
        match self {
            Self::Minimal => "Minimal system calls for basic operations (very restrictive)",
            Self::Network => "Network operations with socket syscalls",
            Self::FileSystem => "File system operations with I/O syscalls",
            Self::Mount => "Mount operations with elevated privileges",
            Self::Daemon => "Daemon operations with monitoring and management",
            Self::Test => "Permissive profile for testing (allows all syscalls)",
        }
    }

    /// Check if profile allows network operations
    pub fn allows_network(&self) -> bool {
        matches!(self, Self::Network | Self::Daemon | Self::Test)
    }

    /// Check if profile allows file system operations
    pub fn allows_filesystem(&self) -> bool {
        matches!(
            self,
            Self::FileSystem | Self::Mount | Self::Daemon | Self::Test
        )
    }

    /// Check if profile allows mount operations
    pub fn allows_mount(&self) -> bool {
        matches!(self, Self::Mount | Self::Daemon | Self::Test)
    }

    /// Get allowed syscalls for this profile
    #[cfg(target_os = "linux")]
    pub fn get_allowed_syscalls(&self) -> Vec<i32> {
        use syscall_numbers::*;

        match self {
            Self::Minimal => vec![
                READ,
                WRITE,
                CLOSE,
                FSTAT,
                LSEEK,
                MMAP,
                MPROTECT,
                MUNMAP,
                BRK,
                RT_SIGACTION,
                RT_SIGPROCMASK,
                RT_SIGRETURN,
                IOCTL,
                PREAD64,
                PWRITE64,
                READV,
                WRITEV,
                ACCESS,
                PIPE,
                SELECT,
                SCHED_YIELD,
                MSYNC,
                MINCORE,
                MADVISE,
                DUP,
                DUP2,
                PAUSE,
                NANOSLEEP,
                GETITIMER,
                ALARM,
                SETITIMER,
                GETPID,
                EXIT_GROUP,
                CLOCK_GETTIME,
                CLOCK_GETRES,
                EPOLL_WAIT,
                EPOLL_CTL,
                TGKILL,
                FUTEX,
                SCHED_SETAFFINITY,
                SCHED_GETAFFINITY,
                EPOLL_CREATE1,
                DUP3,
                PIPE2,
                PSELECT6,
                PPOLL,
                GETCPU,
                FUTEX,
            ],

            Self::Network => {
                let mut syscalls = Self::Minimal.get_allowed_syscalls();
                syscalls.extend_from_slice(&[
                    SOCKET,
                    CONNECT,
                    ACCEPT,
                    SENDTO,
                    RECVFROM,
                    SENDMSG,
                    RECVMSG,
                    SHUTDOWN,
                    BIND,
                    LISTEN,
                    GETSOCKNAME,
                    GETPEERNAME,
                    SOCKETPAIR,
                    SETSOCKOPT,
                    GETSOCKOPT,
                    SENDFILE,
                    ACCEPT4,
                    RECVMMSG,
                ]);
                syscalls
            }

            Self::FileSystem => {
                let mut syscalls = Self::Minimal.get_allowed_syscalls();
                syscalls.extend_from_slice(&[
                    STAT,
                    LSTAT,
                    POLL,
                    OPEN,
                    CREAT,
                    TRUNCATE,
                    FTRUNCATE,
                    GETDENTS,
                    GETCWD,
                    CHDIR,
                    FCHDIR,
                    RENAME,
                    MKDIR,
                    RMDIR,
                    LINK,
                    UNLINK,
                    SYMLINK,
                    READLINK,
                    CHMOD,
                    FCHMOD,
                    CHOWN,
                    FCHOWN,
                    LCHOWN,
                    UMASK,
                    GETTIMEOFDAY,
                    GETRLIMIT,
                    GETRUSAGE,
                    SYSINFO,
                    TIMES,
                    GETUID,
                    GETGID,
                    GETEUID,
                    GETEGID,
                    GETPPID,
                    GETPGRP,
                    GETSID,
                    STATFS,
                    FSTATFS,
                    GETPRIORITY,
                    SETPRIORITY,
                    MLOCK,
                    MUNLOCK,
                    MLOCKALL,
                    MUNLOCKALL,
                    SETRLIMIT,
                    SYNC,
                    CHROOT,
                    SETTIMEOFDAY,
                    UTIMES,
                    NEWFSTATAT,
                    OPENAT,
                    MKDIRAT,
                    FCHOWNAT,
                    FUTIMESAT,
                    UNLINKAT,
                    RENAMEAT,
                    LINKAT,
                    SYMLINKAT,
                    READLINKAT,
                    FCHMODAT,
                    FACCESSAT,
                    UTIME,
                    MKNODAT,
                    FALLOCATE,
                    SYNCFS,
                ]);
                syscalls
            }

            Self::Mount => {
                let mut syscalls = Self::FileSystem.get_allowed_syscalls();
                syscalls.extend_from_slice(&[
                    MOUNT,
                    UMOUNT2,
                    SWAPON,
                    SWAPOFF,
                    PIVOT_ROOT,
                    QUOTACTL,
                    SETUID,
                    SETGID,
                    SETREUID,
                    SETREGID,
                    SETRESUID,
                    SETRESGID,
                    SETPGID,
                    SETSID,
                    CAPGET,
                    CAPSET,
                    INIT_MODULE,
                    DELETE_MODULE,
                    CREATE_MODULE,
                    SETDOMAINNAME,
                    SETHOSTNAME,
                    REBOOT,
                    NFSSERVCTL,
                ]);
                syscalls
            }

            Self::Daemon => {
                let mut syscalls = Self::Mount.get_allowed_syscalls();
                syscalls.extend_from_slice(&[
                    CLONE,
                    FORK,
                    VFORK,
                    EXECVE,
                    WAIT4,
                    KILL,
                    UNAME,
                    SEMGET,
                    SEMOP,
                    SEMCTL,
                    SHMGET,
                    SHMAT,
                    SHMCTL,
                    SHMDT,
                    MSGGET,
                    MSGSND,
                    MSGRCV,
                    MSGCTL,
                    FCNTL,
                    FLOCK,
                    FSYNC,
                    FDATASYNC,
                    SETXATTR,
                    LSETXATTR,
                    FSETXATTR,
                    GETXATTR,
                    LGETXATTR,
                    FGETXATTR,
                    LISTXATTR,
                    LLISTXATTR,
                    FLISTXATTR,
                    REMOVEXATTR,
                    LREMOVEXATTR,
                    FREMOVEXATTR,
                    TKILL,
                    TIME,
                    SCHED_SETPARAM,
                    SCHED_GETPARAM,
                    SCHED_SETSCHEDULER,
                    SCHED_GETSCHEDULER,
                    SCHED_GET_PRIORITY_MAX,
                    SCHED_GET_PRIORITY_MIN,
                    SCHED_RR_GET_INTERVAL,
                    SET_FSUID,
                    SETFSGID,
                    INOTIFY_INIT,
                    INOTIFY_ADD_WATCH,
                    INOTIFY_RM_WATCH,
                    TIMER_CREATE,
                    TIMER_SETTIME,
                    TIMER_GETTIME,
                    TIMER_GETOVERRUN,
                    TIMER_DELETE,
                    CLOCK_SETTIME,
                    CLOCK_NANOSLEEP,
                    SIGNALFD,
                    TIMERFD_CREATE,
                    EVENTFD,
                    TIMERFD_SETTIME,
                    TIMERFD_GETTIME,
                    SIGNALED,
                    EVENTFD2,
                    INOTIFY_INIT1,
                    PREADV,
                    PWRITEV,
                    RT_SIGPENDING,
                    RT_SIGTIMEDWAIT,
                    RT_SIGQUEUEINFO,
                    RT_SIGSUSPEND,
                    SIGALTSTACK,
                    FANOTIFY_INIT,
                    FANOTIFY_MARK,
                    PRLIMIT64,
                    NAME_TO_HANDLE_AT,
                    OPEN_BY_HANDLE_AT,
                    CLOCK_ADJTIME,
                    SENDMMSG,
                    SETNS,
                    PROCESS_VM_READV,
                    PROCESS_VM_WRITEV,
                    KCMP,
                    FINIT_MODULE,
                ]);
                syscalls
            }

            Self::Test => {
                // Allow all syscalls for testing
                (0..=FINIT_MODULE).collect()
            }
        }
    }

    /// Get the default action for this profile
    #[cfg(target_os = "linux")]
    pub fn get_default_action(&self) -> u32 {
        use seccomp_actions::*;

        match self {
            Self::Minimal | Self::Network | Self::FileSystem | Self::Mount => {
                ERRNO | 0x16 // EPERM (Operation not permitted)
            }
            Self::Daemon => {
                LOG // Log violations but don't kill the process
            }
            Self::Test => {
                ALLOW // Allow all syscalls in test mode
            }
        }
    }

    /// Get allowed syscalls for this profile (non-Linux fallback)
    #[cfg(not(target_os = "linux"))]
    pub fn get_allowed_syscalls(&self) -> Vec<i32> {
        // On non-Linux platforms, return empty list since seccomp is not available
        Vec::new()
    }

    /// Get the default action for this profile (non-Linux fallback)
    #[cfg(not(target_os = "linux"))]
    pub fn get_default_action(&self) -> u32 {
        // On non-Linux platforms, return allow action since seccomp is not available
        0x7fff0000 // ALLOW
    }
}

/// System call filter manager
#[derive(Clone)]
pub struct SyscallFilter {
    profile: SeccompProfile,
    initialized: bool,
    allowed_paths: Vec<String>,
    allowed_commands: Vec<String>,
    real_filter_active: bool,
    syscall_count: Arc<Mutex<HashMap<i32, u64>>>,
    violation_count: Arc<Mutex<u64>>,
}

impl SyscallFilter {
    /// Create a new syscall filter with the specified profile
    pub fn new(profile: SeccompProfile) -> Self {
        let (allowed_paths, allowed_commands) = Self::get_profile_rules(profile);

        Self {
            profile,
            initialized: false,
            allowed_paths,
            allowed_commands,
            real_filter_active: false,
            syscall_count: Arc::new(Mutex::new(HashMap::new())),
            violation_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Get profile-specific rules
    fn get_profile_rules(profile: SeccompProfile) -> (Vec<String>, Vec<String>) {
        let allowed_paths = match profile {
            SeccompProfile::Minimal => vec![
                "/dev/null".to_string(),
                "/dev/zero".to_string(),
                "/dev/random".to_string(),
                "/dev/urandom".to_string(),
                "/proc/self".to_string(),
                "/tmp".to_string(),
            ],
            SeccompProfile::Network => vec![
                "/tmp".to_string(),
                "/var/run".to_string(),
                "/dev/null".to_string(),
            ],
            SeccompProfile::FileSystem => vec![
                "/".to_string(),
                "/dev".to_string(),
                "/proc".to_string(),
                "/sys".to_string(),
                "/tmp".to_string(),
                "/var".to_string(),
                "/home".to_string(),
                "/mnt".to_string(),
                "/media".to_string(),
            ],
            SeccompProfile::Mount => vec![
                "/".to_string(),
                "/dev".to_string(),
                "/proc".to_string(),
                "/sys".to_string(),
                "/etc".to_string(),
                "/bin".to_string(),
                "/sbin".to_string(),
                "/usr/bin".to_string(),
                "/usr/sbin".to_string(),
                "/tmp".to_string(),
                "/var".to_string(),
                "/mnt".to_string(),
                "/media".to_string(),
            ],
            SeccompProfile::Daemon => vec![
                "/".to_string(),
                "/dev".to_string(),
                "/proc".to_string(),
                "/sys".to_string(),
                "/etc".to_string(),
                "/bin".to_string(),
                "/sbin".to_string(),
                "/usr/bin".to_string(),
                "/usr/sbin".to_string(),
                "/tmp".to_string(),
                "/var".to_string(),
                "/home".to_string(),
                "/mnt".to_string(),
                "/media".to_string(),
                "/opt".to_string(),
                "/srv".to_string(),
            ],
            SeccompProfile::Test => vec!["/".to_string()],
        };

        let allowed_commands = match profile {
            SeccompProfile::Minimal => {
                vec!["echo".to_string(), "cat".to_string(), "wc".to_string()]
            }
            SeccompProfile::Network => vec![
                "ssh".to_string(),
                "sshfs".to_string(),
                "nc".to_string(),
                "telnet".to_string(),
                "curl".to_string(),
                "wget".to_string(),
                "mount".to_string(),
                "umount".to_string(),
                "smbclient".to_string(),
            ],
            SeccompProfile::FileSystem => vec![
                "ls".to_string(),
                "cp".to_string(),
                "mv".to_string(),
                "rm".to_string(),
                "mkdir".to_string(),
                "rmdir".to_string(),
                "chmod".to_string(),
                "chown".to_string(),
                "chgrp".to_string(),
                "find".to_string(),
                "grep".to_string(),
                "sed".to_string(),
                "awk".to_string(),
                "mount".to_string(),
                "umount".to_string(),
            ],
            SeccompProfile::Mount => vec![
                "mount".to_string(),
                "umount".to_string(),
                "mount.nfs".to_string(),
                "mount.nfs4".to_string(),
                "mount.cifs".to_string(),
                "umount.nfs".to_string(),
                "systemctl".to_string(),
                "service".to_string(),
            ],
            SeccompProfile::Daemon => vec![
                "mount".to_string(),
                "umount".to_string(),
                "systemctl".to_string(),
                "service".to_string(),
                "ps".to_string(),
                "kill".to_string(),
                "killall".to_string(),
                "pgrep".to_string(),
                "pkill".to_string(),
                "nohup".to_string(),
                "daemon".to_string(),
                "init".to_string(),
                "shutdown".to_string(),
                "reboot".to_string(),
                "poweroff".to_string(),
            ],
            SeccompProfile::Test => vec![
                // Allow all commands for testing
            ],
        };

        (allowed_paths, allowed_commands)
    }

    /// Initialize seccomp filtering for the current thread
    pub fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        info!(
            "Initializing syscall filter with profile: {:?}",
            self.profile
        );

        #[cfg(target_os = "linux")]
        {
            if self.profile != SeccompProfile::Test {
                // Try to set up real seccomp filtering
                match self.setup_real_seccomp() {
                    Ok(_) => {
                        self.real_filter_active = true;
                        info!("Real seccomp filtering activated");
                    }
                    Err(e) => {
                        warn!(
                            "Failed to set up real seccomp filtering: {}. Using validation mode.",
                            e
                        );
                        // Fall back to validation mode
                    }
                }
            }
        }

        self.initialized = true;
        info!("Syscall filter successfully initialized");
        Ok(())
    }

    /// Set up real Linux seccomp filtering
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn setup_real_seccomp(&self) -> Result<()> {
        use libc::{prctl, SECCOMP_MODE_FILTER};
        use seccomp_actions::*;
        use syscall_numbers::*;

        // Build the BPF filter program
        let mut builder = SeccompFilterBuilder::new(self.profile.get_default_action());

        let allowed_syscalls = self.profile.get_allowed_syscalls();
        for syscall in allowed_syscalls {
            builder.add_syscall(syscall);
        }

        let filter_program = builder.build()?;

        // Create sock_fprog structure
        let prog = sock_fprog {
            len: filter_program.len() as u16,
            filter: filter_program.as_ptr(),
        };

        // Set no new privileges first
        unsafe {
            if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(anyhow!("Failed to set no new privileges"));
            }

            // Load the seccomp filter
            if libc::syscall(
                __NR_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_MODE_FILTER,
                &prog as *const _ as usize,
            ) as i32
                != 0
            {
                return Err(anyhow!("Failed to load seccomp filter"));
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn setup_real_seccomp(&self) -> Result<()> {
        // Non-Linux systems don't support seccomp
        Err(anyhow!("Seccomp filtering not supported on this platform"))
    }

    /// Validate a command against the current profile
    pub fn validate_command(&self, command: &str) -> Result<()> {
        if self.profile == SeccompProfile::Test {
            return Ok(());
        }

        let command_name = Path::new(command)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(command);

        if !self.allowed_commands.contains(&command_name.to_string()) {
            return Err(anyhow!(
                "Command '{}' is not allowed in {:?} profile",
                command_name,
                self.profile
            ));
        }

        Ok(())
    }

    /// Validate a path against the current profile
    pub fn validate_path(&self, path: &Path) -> Result<()> {
        if self.profile == SeccompProfile::Test {
            return Ok(());
        }

        let path_str = path.to_string_lossy();

        // Check if path is under an allowed directory
        for allowed_path in &self.allowed_paths {
            if path_str.starts_with(allowed_path) {
                return Ok(());
            }
        }

        return Err(anyhow!(
            "Path '{}' is not allowed in {:?} profile",
            path_str,
            self.profile
        ));
    }

    /// Validate file descriptor access
    pub fn validate_fd_access(&self, fd: RawFd, operation: &str) -> Result<()> {
        // In a real implementation, this would check fd against allowed operations
        // For now, we just log the validation attempt
        debug!(
            "Validating fd {} operation '{}' in {:?} profile",
            fd, operation, self.profile
        );
        Ok(())
    }

    /// Get the current profile
    pub fn profile(&self) -> SeccompProfile {
        self.profile
    }

    /// Check if seccomp is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Check if real seccomp filtering is active
    pub fn is_real_filter_active(&self) -> bool {
        self.real_filter_active
    }

    /// Get allowed commands for the profile
    pub fn allowed_commands(&self) -> &[String] {
        &self.allowed_commands
    }

    /// Get allowed paths for the profile
    pub fn allowed_paths(&self) -> &[String] {
        &self.allowed_paths
    }

    /// Get syscall statistics
    pub fn get_syscall_stats(&self) -> HashMap<i32, u64> {
        if let Ok(counts) = self.syscall_count.lock() {
            counts.clone()
        } else {
            HashMap::new()
        }
    }

    /// Get violation count
    pub fn get_violation_count(&self) -> u64 {
        if let Ok(count) = self.violation_count.lock() {
            *count
        } else {
            0
        }
    }

    /// Reset statistics
    pub fn reset_stats(&self) -> Result<()> {
        if let Ok(mut counts) = self.syscall_count.lock() {
            counts.clear();
        }
        if let Ok(mut violations) = self.violation_count.lock() {
            *violations = 0;
        }
        Ok(())
    }

    /// Log a syscall usage (for monitoring)
    pub fn log_syscall(&self, syscall_num: i32, operation: &str) {
        if self.profile == SeccompProfile::Test {
            return; // Don't log in test mode
        }

        debug!("Syscall {} used for operation: {}", syscall_num, operation);

        // Update syscall count
        if let Ok(mut counts) = self.syscall_count.lock() {
            *counts.entry(syscall_num).or_insert(0) += 1;
        }
    }

    /// Log a seccomp violation (for security monitoring)
    pub fn log_violation(&self, syscall_num: i32, operation: &str) {
        if self.profile == SeccompProfile::Test {
            return; // Don't log in test mode
        }

        warn!(
            "Seccomp violation detected: syscall {} not allowed for operation '{}' in {:?} profile",
            syscall_num, operation, self.profile
        );

        // Update violation count
        if let Ok(mut violations) = self.violation_count.lock() {
            *violations += 1;
        }
    }

    /// Check if a syscall is allowed by this profile
    pub fn is_syscall_allowed(&self, syscall_num: i32) -> bool {
        self.profile.get_allowed_syscalls().contains(&syscall_num)
    }

    /// Get detailed profile information
    pub fn get_profile_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();

        info.insert("name".to_string(), format!("{:?}", self.profile));
        info.insert(
            "description".to_string(),
            self.profile.description().to_string(),
        );
        info.insert(
            "allows_network".to_string(),
            self.profile.allows_network().to_string(),
        );
        info.insert(
            "allows_filesystem".to_string(),
            self.profile.allows_filesystem().to_string(),
        );
        info.insert(
            "allows_mount".to_string(),
            self.profile.allows_mount().to_string(),
        );
        info.insert(
            "real_filter_active".to_string(),
            self.real_filter_active.to_string(),
        );
        info.insert(
            "allowed_syscalls_count".to_string(),
            self.profile.get_allowed_syscalls().len().to_string(),
        );
        info.insert(
            "default_action".to_string(),
            format!("0x{:x}", self.profile.get_default_action()),
        );

        info
    }
}

/// Secure process executor with syscall validation
#[derive(Clone)]
pub struct SecureExecutor {
    filter: SyscallFilter,
}

impl SecureExecutor {
    /// Create a new secure executor with the specified profile
    pub fn new(profile: SeccompProfile) -> Result<Self> {
        Ok(Self {
            filter: SyscallFilter::new(profile),
        })
    }

    /// Initialize the seccomp filter
    pub fn initialize(&mut self) -> Result<()> {
        self.filter.initialize()
    }

    /// Execute a function within a secure context
    pub fn execute_in_sandbox<F, R>(&mut self, f: F) -> Result<R>
    where
        F: FnOnce() -> Result<R>,
    {
        // Initialize syscall filter
        self.filter.initialize()?;

        // Execute the function
        f()
    }

    /// Get the seccomp profile
    pub fn profile(&self) -> SeccompProfile {
        self.filter.profile()
    }

    /// Validate a command for execution
    pub fn validate_command(&self, command: &str) -> Result<()> {
        self.filter.validate_command(command)
    }

    /// Validate a path for access
    pub fn validate_path(&self, path: &Path) -> Result<()> {
        self.filter.validate_path(path)
    }

    /// Validate an operation for execution
    pub fn validate_operation(&self, operation: &str) -> Result<()> {
        // Check if operation is allowed in current profile
        match self.profile() {
            SeccompProfile::Minimal => {
                if !["read", "write", "socket_read", "socket_write"].contains(&operation) {
                    return Err(anyhow!(
                        "Operation '{}' not allowed in Minimal profile",
                        operation
                    ));
                }
            }
            SeccompProfile::Network => {
                if ![
                    "read",
                    "write",
                    "socket_read",
                    "socket_write",
                    "connect",
                    "bind",
                    "listen",
                ]
                .contains(&operation)
                {
                    return Err(anyhow!(
                        "Operation '{}' not allowed in Network profile",
                        operation
                    ));
                }
            }
            SeccompProfile::FileSystem => {
                if ![
                    "read",
                    "write",
                    "socket_read",
                    "socket_write",
                    "open",
                    "close",
                    "stat",
                ]
                .contains(&operation)
                {
                    return Err(anyhow!(
                        "Operation '{}' not allowed in FileSystem profile",
                        operation
                    ));
                }
            }
            SeccompProfile::Mount => {
                if ![
                    "read",
                    "write",
                    "socket_read",
                    "socket_write",
                    "open",
                    "close",
                    "stat",
                    "mount",
                    "umount",
                ]
                .contains(&operation)
                {
                    return Err(anyhow!(
                        "Operation '{}' not allowed in Mount profile",
                        operation
                    ));
                }
            }
            SeccompProfile::Daemon => {
                // Daemon profile allows most operations
            }
            SeccompProfile::Test => {
                // Test profile allows all operations
            }
        }

        debug!(
            "Validated operation '{}' in {:?} profile",
            operation,
            self.profile()
        );
        Ok(())
    }
}

/// Global seccomp manager for daemon processes
pub struct GlobalSeccompManager {
    filters: HashMap<String, SyscallFilter>,
    default_profile: SeccompProfile,
    global_stats: Arc<Mutex<HashMap<String, u64>>>,
    total_violations: Arc<Mutex<u64>>,
}

#[allow(dead_code)]
impl GlobalSeccompManager {
    /// Create a new global seccomp manager
    pub fn new(default_profile: SeccompProfile) -> Self {
        Self {
            filters: HashMap::new(),
            default_profile,
            global_stats: Arc::new(Mutex::new(HashMap::new())),
            total_violations: Arc::new(Mutex::new(0)),
        }
    }

    /// Initialize seccomp for a specific operation
    pub fn initialize_operation(
        &mut self,
        operation: &str,
        profile: Option<SeccompProfile>,
    ) -> Result<()> {
        let profile = profile.unwrap_or(self.default_profile);
        let mut filter = SyscallFilter::new(profile);

        // Initialize the filter (this will set up real seccomp if possible)
        filter.initialize()?;
        self.filters.insert(operation.to_string(), filter);

        info!(
            "Initialized seccomp for operation: {} with profile: {:?}",
            operation, profile
        );

        // Add to global stats
        if let Ok(mut stats) = self.global_stats.lock() {
            stats.insert(format!("operation:{}", operation), 0);
        }

        Ok(())
    }

    /// Check if an operation is initialized
    pub fn is_operation_initialized(&self, operation: &str) -> bool {
        self.filters
            .get(operation)
            .map_or(false, |f| f.is_initialized())
    }

    /// Get profile for an operation
    pub fn operation_profile(&self, operation: &str) -> Option<SeccompProfile> {
        self.filters.get(operation).map(|f| f.profile())
    }

    /// Get filter for an operation
    pub fn get_operation_filter(&self, operation: &str) -> Option<&SyscallFilter> {
        self.filters.get(operation)
    }

    /// Remove an operation's filter
    pub fn remove_operation(&mut self, operation: &str) -> Option<SyscallFilter> {
        let filter = self.filters.remove(operation);

        // Remove from global stats
        if let Ok(mut stats) = self.global_stats.lock() {
            stats.remove(&format!("operation:{}", operation));
        }

        filter
    }

    /// List all operations
    pub fn list_operations(&self) -> Vec<String> {
        self.filters.keys().cloned().collect()
    }

    /// Get global statistics
    pub fn get_global_stats(&self) -> (HashMap<String, u64>, u64) {
        let stats = if let Ok(s) = self.global_stats.lock() {
            s.clone()
        } else {
            HashMap::new()
        };

        let violations = if let Ok(v) = self.total_violations.lock() {
            *v
        } else {
            0
        };

        (stats, violations)
    }

    /// Get comprehensive security report
    pub fn get_security_report(&self) -> HashMap<String, String> {
        let mut report = HashMap::new();

        let mut total_filters = 0;
        let mut active_filters = 0;
        let mut real_filters = 0;

        for (operation, filter) in &self.filters {
            total_filters += 1;
            if filter.is_initialized() {
                active_filters += 1;
            }
            if filter.is_real_filter_active() {
                real_filters += 1;
            }

            let info = filter.get_profile_info();
            for (key, value) in info {
                report.insert(format!("operations.{}.{}", operation, key), value);
            }
        }

        let (stats, violations) = self.get_global_stats();

        report.insert("total_filters".to_string(), total_filters.to_string());
        report.insert("active_filters".to_string(), active_filters.to_string());
        report.insert("real_filters".to_string(), real_filters.to_string());
        report.insert("total_violations".to_string(), violations.to_string());
        report.insert(
            "default_profile".to_string(),
            format!("{:?}", self.default_profile),
        );

        // Add operation statistics
        for (key, count) in stats {
            report.insert(key, count.to_string());
        }

        report
    }

    /// Reset all statistics
    pub fn reset_all_stats(&self) -> Result<()> {
        // Reset individual filter stats
        for filter in self.filters.values() {
            filter.reset_stats()?;
        }

        // Reset global stats
        if let Ok(mut stats) = self.global_stats.lock() {
            stats.clear();
        }
        if let Ok(mut violations) = self.total_violations.lock() {
            *violations = 0;
        }

        Ok(())
    }

    /// Check system security status
    pub fn check_security_status(&self) -> Result<HashMap<String, String>> {
        let mut status = HashMap::new();

        // Check if seccomp is available and working
        #[cfg(target_os = "linux")]
        {
            let real_count = self
                .filters
                .values()
                .filter(|f| f.is_real_filter_active())
                .count();
            if real_count > 0 {
                status.insert("seccomp_status".to_string(), "Active".to_string());
                status.insert("real_filters_count".to_string(), real_count.to_string());
            } else {
                status.insert("seccomp_status".to_string(), "Validation Only".to_string());
                status.insert("real_filters_count".to_string(), "0".to_string());
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            status.insert("seccomp_status".to_string(), "Not Supported".to_string());
            status.insert("real_filters_count".to_string(), "0".to_string());
        }

        // Check for violations
        let violations = self.get_violation_count();
        if violations > 0 {
            status.insert(
                "security_status".to_string(),
                "Violations Detected".to_string(),
            );
            status.insert(
                "violation_severity".to_string(),
                if violations > 100 {
                    "High".to_string()
                } else if violations > 10 {
                    "Medium".to_string()
                } else {
                    "Low".to_string()
                },
            );
        } else {
            status.insert("security_status".to_string(), "Secure".to_string());
            status.insert("violation_severity".to_string(), "None".to_string());
        }

        status.insert(
            "monitored_operations".to_string(),
            self.filters.len().to_string(),
        );

        Ok(status)
    }

    /// Get total violation count across all operations
    pub fn get_violation_count(&self) -> u64 {
        let mut total = 0;
        for filter in self.filters.values() {
            total += filter.get_violation_count();
        }
        total
    }

    /// Apply seccomp to daemon main process
    pub fn apply_daemon_seccomp(&mut self, strict_mode: bool) -> Result<()> {
        let profile = if strict_mode {
            SeccompProfile::Minimal
        } else {
            SeccompProfile::Daemon
        };

        info!(
            "Applying seccomp to daemon process with profile: {:?}",
            profile
        );
        self.initialize_operation("daemon_main", Some(profile))
    }
}

/// Convenience function to create a seccomp filter for testing
pub fn create_test_filter() -> Result<SyscallFilter> {
    let mut filter = SyscallFilter::new(SeccompProfile::Test);
    filter.initialize()?;
    Ok(filter)
}

/// Convenience function to create a seccomp filter for daemon operations
pub fn create_daemon_filter() -> Result<SyscallFilter> {
    let mut filter = SyscallFilter::new(SeccompProfile::Daemon);
    filter.initialize()?;
    Ok(filter)
}

/// Convenience function to create a seccomp filter for mount operations
pub fn create_mount_filter() -> Result<SyscallFilter> {
    let mut filter = SyscallFilter::new(SeccompProfile::Mount);
    filter.initialize()?;
    Ok(filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_profile_properties() {
        assert!(SeccompProfile::Network.allows_network());
        assert!(!SeccompProfile::Minimal.allows_network());

        assert!(SeccompProfile::FileSystem.allows_filesystem());
        assert!(!SeccompProfile::Network.allows_filesystem());

        assert!(SeccompProfile::Mount.allows_mount());
        assert!(!SeccompProfile::FileSystem.allows_mount());
    }

    #[test]
    fn test_secure_executor_creation() {
        let executor = SecureExecutor::new(SeccompProfile::Test);
        assert!(executor.is_ok());
        assert_eq!(executor.unwrap().profile(), SeccompProfile::Test);
    }

    #[test]
    fn test_global_seccomp_manager() {
        let mut manager = GlobalSeccompManager::new(SeccompProfile::Daemon);

        assert!(!manager.is_operation_initialized("test"));

        let result = manager.initialize_operation("test", Some(SeccompProfile::Test));
        assert!(result.is_ok());

        assert_eq!(
            manager.operation_profile("test"),
            Some(SeccompProfile::Test)
        );
    }

    #[test]
    fn test_command_validation() {
        let filter = SyscallFilter::new(SeccompProfile::Mount);

        // Allowed commands
        assert!(filter.validate_command("mount").is_ok());
        assert!(filter.validate_command("umount").is_ok());
        assert!(filter.validate_command("/bin/mount").is_ok());

        // Blocked commands
        assert!(filter.validate_command("rm").is_err());
        assert!(filter.validate_command("bash").is_err());
        assert!(filter.validate_command("sh").is_err());
    }

    #[test]
    fn test_path_validation() {
        let filter = SyscallFilter::new(SeccompProfile::Minimal);

        // Allowed paths
        assert!(filter.validate_path(Path::new("/dev/null")).is_ok());
        assert!(filter.validate_path(Path::new("/tmp/test")).is_ok());
        assert!(filter.validate_path(Path::new("/proc/self/status")).is_ok());

        // Blocked paths
        assert!(filter.validate_path(Path::new("/etc/passwd")).is_err());
        assert!(filter.validate_path(Path::new("/root/.ssh")).is_err());
        assert!(filter.validate_path(Path::new("/home/user")).is_err());
    }

    #[test]
    fn test_profile_specific_rules() {
        let network_filter = SyscallFilter::new(SeccompProfile::Network);
        assert!(network_filter.validate_command("sshfs").is_ok());
        assert!(network_filter.validate_command("mount").is_ok());
        assert!(network_filter.validate_command("rm").is_err());

        let mount_filter = SyscallFilter::new(SeccompProfile::Mount);
        assert!(mount_filter.validate_command("mount.nfs").is_ok());
        assert!(mount_filter.validate_command("systemctl").is_ok());
        assert!(mount_filter.validate_command("curl").is_err());
    }
}
