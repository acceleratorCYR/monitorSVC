/*#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <sys/ptrace.h>
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <elf.h>
#include <unistd.h>
#include <errno.h>       
#include <sys/mman.h>

#define _XOPEN_SOURCE 500  /* include pread,pwrite */
#define _GNU_SOURCE

const int long_size = sizeof(long);

char *sysCallNameStr[398];


int excludeSysCall[400] = {0};
int includeSysCall[400] = {0};

int isInclude = 0;


long getSysCallNo(int pid, struct pt_regs *regs)
{
	long scno = 0;
	ptrace(PTRACE_GETREGS, pid, NULL, regs);
	scno = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs->ARM_pc - 4), NULL);
	if(scno == 0)
		return 0;

	if(scno == 0xef000000)
		scno = regs->ARM_r7;
	else
	{
		if((scno & 0x0ff00000) != 0x0f900000)
			return -1;

		scno &= 0x000fffff;
	}

	return scno;
}

void reverse(char *str)
{
	int i, j;
	char temp;
	for(i=0,j=strlen(str)-2;i<=j;++i,--j)
	{
		temp = str[i];
		str[i] = str[j];
		str[j] = temp;
	}
}

void getdata(pid_t pid, long addr, char *str, int len)
{
	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[long_size];
	} data;

	i=0;
	j=len/long_size;
	laddr = str;
	while(i<j){
		data.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * 4, NULL);
		memcpy(laddr, data.chars, long_size);
		++i;
		laddr += long_size;	
	}

	j = len % long_size;
	if(j != 0)
	{
		data.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * 4, NULL);
		memcpy(laddr, data.chars, j);
	}

	str[len] = '\0';
}

void putdata(pid_t pid, long addr, char *str, int len)
{
	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[long_size];

	}data;

	i = 0;
	j = len/long_size;

	laddr = str;

	while(i < j)
	{
		memcpy(data.chars, laddr, long_size);
		ptrace(PTRACE_POKEDATA, pid, addr + i * 4, data.val);
		++i;
		laddr += long_size;
	}

	j = len % long_size;
	if(j != 0)
	{
		memcpy(data.chars, laddr, j);
		ptrace(PTRACE_POKEDATA, pid, addr + i * 4, data.val);
	}
}

void peek_str(pid_t pid, long baddr, char target[])
{
    union{
        long val;
        char chars[long_size];
    }data;

    long offset=0;
    int done = 0, i;
    target[0] = '\0';

    while(!done){
        data.val = ptrace(PTRACE_PEEKTEXT, pid, baddr + offset, NULL);
        strncat(target, data.chars, long_size);
        for(i = 0; i < long_size; i++)
        {
            if(data.chars[i] == '\0')
                done = 1;
        }
        offset += long_size;
    }
}

void tracePro(int pid)
{
	long scno = 0;
	struct pt_regs regs;
	char *str;

	scno = getSysCallNo(pid, &regs);
    if(regs.ARM_ip == 0)
    {//enter function
        return;
    }

	if(isInclude)
	{
		if(scno >= 0 && scno < sizeof(sysCallNameStr) && includeSysCall[scno])
		{
			;
		}else
			return;
	}

	if(scno >= 0 && scno < sizeof(sysCallNameStr) && !excludeSysCall[scno])
	{
		;
	}else
		return;

	if(scno == __NR_write)
	{
		str = (char *)malloc((regs.ARM_r2 + 1)* sizeof(char));
        //size_t write(int fd, const void *buf, size_t count);
		getdata(pid, regs.ARM_r1, str, regs.ARM_r2);
		reverse(str);
		putdata(pid, regs.ARM_r1, str, regs.ARM_r2);
		//printf("Reverse str. long_size:%d\n", long_size);
		free(str);
	}else if(scno == __NR_open)
    {
        printf("__NR_open is called\n");
        char fileName[255];
        memset(fileName, 0, 255);
        peek_str(pid, regs.ARM_r0, fileName);
        printf("open file: %s\n",fileName);
    }else if(scno == __NR_openat)
    {
        char fileName[255];
        memset(fileName, 0, 255);
        peek_str(pid, regs.ARM_r1, fileName);
        printf("openat file: %s\n",fileName);
    }else
    {
    	if(scno >= 0 && scno < sizeof(sysCallNameStr) && strcmp(sysCallNameStr[scno], ""))
    	{
    		printf("Target syscall %s\n", sysCallNameStr[scno]);
    	}else
        	printf("Target syscall no:%ld\n", scno);
    }

}

#define HELPSTR "\n\
	Usage:%s -p $pid <pid to be traced>\n\
	[-L] <list sysCallTable>\n\
	[-v sysCallNo]* <ignore sysCallNo>\n\
	[-e sysCallNo]* <filter sysCallNo>\n\
"

#define SYSCALLTABLE "\n\
SysCallNo SysCallName\n\
   0          __NR_restart_syscall \n\
   1          __NR_exit \n\
   2          __NR_fork \n\
   3          __NR_read \n\
   4          __NR_write \n\
   5          __NR_open \n\
   6          __NR_close \n\
   8          __NR_creat \n\
   9          __NR_link \n\
   10          __NR_unlink \n\
   11          __NR_execve \n\
   12          __NR_chdir \n\
   14          __NR_mknod \n\
   15          __NR_chmod \n\
   16          __NR_lchown \n\
   19          __NR_lseek \n\
   20          __NR_getpid \n\
   21          __NR_mount \n\
   23          __NR_setuid \n\
   24          __NR_getuid \n\
   26          __NR_ptrace \n\
   29          __NR_pause \n\
   33          __NR_access \n\
   34          __NR_nice \n\
   36          __NR_sync \n\
   37          __NR_kill \n\
   38          __NR_rename \n\
   39          __NR_mkdir \n\
   40          __NR_rmdir \n\
   41          __NR_dup \n\
   42          __NR_pipe \n\
   43          __NR_times \n\
   45          __NR_brk \n\
   46          __NR_setgid \n\
   47          __NR_getgid \n\
   49          __NR_geteuid \n\
   50          __NR_getegid \n\
   51          __NR_acct \n\
   52          __NR_umount2 \n\
   54          __NR_ioctl \n\
   55          __NR_fcntl \n\
   57          __NR_setpgid \n\
   60          __NR_umask \n\
   61          __NR_chroot \n\
   62          __NR_ustat \n\
   63          __NR_dup2 \n\
   64          __NR_getppid \n\
   65          __NR_getpgrp \n\
   66          __NR_setsid \n\
   67          __NR_sigaction \n\
   70          __NR_setreuid \n\
   71          __NR_setregid \n\
   72          __NR_sigsuspend \n\
   73          __NR_sigpending \n\
   74          __NR_sethostname \n\
   75          __NR_setrlimit \n\
   77          __NR_getrusage \n\
   78          __NR_gettimeofday \n\
   79          __NR_settimeofday \n\
   80          __NR_getgroups \n\
   81          __NR_setgroups \n\
   83          __NR_symlink \n\
   85          __NR_readlink \n\
   86          __NR_uselib \n\
   87          __NR_swapon \n\
   88          __NR_reboot \n\
   91          __NR_munmap \n\
   92          __NR_truncate \n\
   93          __NR_ftruncate \n\
   94          __NR_fchmod \n\
   95          __NR_fchown \n\
   96          __NR_getpriority \n\
   97          __NR_setpriority \n\
   99          __NR_statfs \n\
   100          __NR_fstatfs \n\
   103          __NR_syslog \n\
   104          __NR_setitimer \n\
   105          __NR_getitimer \n\
   106          __NR_stat \n\
   107          __NR_lstat \n\
   108          __NR_fstat \n\
   111          __NR_vhangup \n\
   114          __NR_wait4 \n\
   115          __NR_swapoff \n\
   116          __NR_sysinfo \n\
   118          __NR_fsync \n\
   119          __NR_sigreturn \n\
   120          __NR_clone \n\
   121          __NR_setdomainname \n\
   122          __NR_uname \n\
   124          __NR_adjtimex \n\
   125          __NR_mprotect \n\
   126          __NR_sigprocmask \n\
   128          __NR_init_module \n\
   129          __NR_delete_module \n\
   131          __NR_quotactl \n\
   132          __NR_getpgid \n\
   133          __NR_fchdir \n\
   134          __NR_bdflush \n\
   135          __NR_sysfs \n\
   136          __NR_personality \n\
   138          __NR_setfsuid \n\
   139          __NR_setfsgid \n\
   140          __NR__llseek \n\
   141          __NR_getdents \n\
   142          __NR__newselect \n\
   143          __NR_flock \n\
   144          __NR_msync \n\
   145          __NR_readv \n\
   146          __NR_writev \n\
   147          __NR_getsid \n\
   148          __NR_fdatasync \n\
   149          __NR__sysctl \n\
   150          __NR_mlock \n\
   151          __NR_munlock \n\
   152          __NR_mlockall \n\
   153          __NR_munlockall \n\
   154          __NR_sched_setparam \n\
   155          __NR_sched_getparam \n\
   156          __NR_sched_setscheduler \n\
   157          __NR_sched_getscheduler \n\
   158          __NR_sched_yield \n\
   159          __NR_sched_get_priority_max \n\
   160          __NR_sched_get_priority_min \n\
   161          __NR_sched_rr_get_interval \n\
   162          __NR_nanosleep \n\
   163          __NR_mremap \n\
   164          __NR_setresuid \n\
   165          __NR_getresuid \n\
   168          __NR_poll \n\
   169          __NR_nfsservctl \n\
   170          __NR_setresgid \n\
   171          __NR_getresgid \n\
   172          __NR_prctl \n\
   173          __NR_rt_sigreturn \n\
   174          __NR_rt_sigaction \n\
   175          __NR_rt_sigprocmask \n\
   176          __NR_rt_sigpending \n\
   177          __NR_rt_sigtimedwait \n\
   178          __NR_rt_sigqueueinfo \n\
   179          __NR_rt_sigsuspend \n\
   180          __NR_pread64 \n\
   181          __NR_pwrite64 \n\
   182          __NR_chown \n\
   183          __NR_getcwd \n\
   184          __NR_capget \n\
   185          __NR_capset \n\
   186          __NR_sigaltstack \n\
   187          __NR_sendfile \n\
   190          __NR_vfork \n\
   191          __NR_ugetrlimit \n\
   192          __NR_mmap2 \n\
   193          __NR_truncate64 \n\
   194          __NR_ftruncate64 \n\
   195          __NR_stat64 \n\
   196          __NR_lstat64 \n\
   197          __NR_fstat64 \n\
   198          __NR_lchown32 \n\
   199          __NR_getuid32 \n\
   200          __NR_getgid32 \n\
   201          __NR_geteuid32 \n\
   202          __NR_getegid32 \n\
   203          __NR_setreuid32 \n\
   204          __NR_setregid32 \n\
   205          __NR_getgroups32 \n\
   206          __NR_setgroups32 \n\
   207          __NR_fchown32 \n\
   208          __NR_setresuid32 \n\
   209          __NR_getresuid32 \n\
   210          __NR_setresgid32 \n\
   211          __NR_getresgid32 \n\
   212          __NR_chown32 \n\
   213          __NR_setuid32 \n\
   214          __NR_setgid32 \n\
   215          __NR_setfsuid32 \n\
   216          __NR_setfsgid32 \n\
   217          __NR_getdents64 \n\
   218          __NR_pivot_root \n\
   219          __NR_mincore \n\
   220          __NR_madvise \n\
   221          __NR_fcntl64 \n\
   224          __NR_gettid \n\
   225          __NR_readahead \n\
   226          __NR_setxattr \n\
   227          __NR_lsetxattr \n\
   228          __NR_fsetxattr \n\
   229          __NR_getxattr \n\
   230          __NR_lgetxattr \n\
   231          __NR_fgetxattr \n\
   232          __NR_listxattr \n\
   233          __NR_llistxattr \n\
   234          __NR_flistxattr \n\
   235          __NR_removexattr \n\
   236          __NR_lremovexattr \n\
   237          __NR_fremovexattr \n\
   238          __NR_tkill \n\
   239          __NR_sendfile64 \n\
   240          __NR_futex \n\
   241          __NR_sched_setaffinity \n\
   242          __NR_sched_getaffinity \n\
   243          __NR_io_setup \n\
   244          __NR_io_destroy \n\
   245          __NR_io_getevents \n\
   246          __NR_io_submit \n\
   247          __NR_io_cancel \n\
   248          __NR_exit_group \n\
   249          __NR_lookup_dcookie \n\
   250          __NR_epoll_create \n\
   251          __NR_epoll_ctl \n\
   252          __NR_epoll_wait \n\
   253          __NR_remap_file_pages \n\
   256          __NR_set_tid_address \n\
   257          __NR_timer_create \n\
   258          __NR_timer_settime \n\
   259          __NR_timer_gettime \n\
   260          __NR_timer_getoverrun \n\
   261          __NR_timer_delete \n\
   262          __NR_clock_settime \n\
   263          __NR_clock_gettime \n\
   264          __NR_clock_getres \n\
   265          __NR_clock_nanosleep \n\
   266          __NR_statfs64 \n\
   267          __NR_fstatfs64 \n\
   268          __NR_tgkill \n\
   269          __NR_utimes \n\
   270          __NR_arm_fadvise64_64 \n\
   271          __NR_pciconfig_iobase \n\
   272          __NR_pciconfig_read \n\
   273          __NR_pciconfig_write \n\
   274          __NR_mq_open \n\
   275          __NR_mq_unlink \n\
   276          __NR_mq_timedsend \n\
   277          __NR_mq_timedreceive \n\
   278          __NR_mq_notify \n\
   279          __NR_mq_getsetattr \n\
   280          __NR_waitid \n\
   281          __NR_socket \n\
   282          __NR_bind \n\
   283          __NR_connect \n\
   284          __NR_listen \n\
   285          __NR_accept \n\
   286          __NR_getsockname \n\
   287          __NR_getpeername \n\
   288          __NR_socketpair \n\
   289          __NR_send \n\
   290          __NR_sendto \n\
   291          __NR_recv \n\
   292          __NR_recvfrom \n\
   293          __NR_shutdown \n\
   294          __NR_setsockopt \n\
   295          __NR_getsockopt \n\
   296          __NR_sendmsg \n\
   297          __NR_recvmsg \n\
   298          __NR_semop \n\
   299          __NR_semget \n\
   300          __NR_semctl \n\
   301          __NR_msgsnd \n\
   302          __NR_msgrcv \n\
   303          __NR_msgget \n\
   304          __NR_msgctl \n\
   305          __NR_shmat \n\
   306          __NR_shmdt \n\
   307          __NR_shmget \n\
   308          __NR_shmctl \n\
   309          __NR_add_key \n\
   310          __NR_request_key \n\
   311          __NR_keyctl \n\
   312          __NR_semtimedop \n\
   313          __NR_vserver \n\
   314          __NR_ioprio_set \n\
   315          __NR_ioprio_get \n\
   316          __NR_inotify_init \n\
   317          __NR_inotify_add_watch \n\
   318          __NR_inotify_rm_watch \n\
   319          __NR_mbind \n\
   320          __NR_get_mempolicy \n\
   321          __NR_set_mempolicy \n\
   322          __NR_openat \n\
   323          __NR_mkdirat \n\
   324          __NR_mknodat \n\
   325          __NR_fchownat \n\
   326          __NR_futimesat \n\
   327          __NR_fstatat64 \n\
   328          __NR_unlinkat \n\
   329          __NR_renameat \n\
   330          __NR_linkat \n\
   331          __NR_symlinkat \n\
   332          __NR_readlinkat \n\
   333          __NR_fchmodat \n\
   334          __NR_faccessat \n\
   335          __NR_pselect6 \n\
   336          __NR_ppoll \n\
   337          __NR_unshare \n\
   338          __NR_set_robust_list \n\
   339          __NR_get_robust_list \n\
   340          __NR_splice \n\
   341          __NR_arm_sync_file_range \n\
   342          __NR_tee \n\
   343          __NR_vmsplice \n\
   344          __NR_move_pages \n\
   345          __NR_getcpu \n\
   346          __NR_epoll_pwait \n\
   347          __NR_kexec_load \n\
   348          __NR_utimensat \n\
   349          __NR_signalfd \n\
   350          __NR_timerfd_create \n\
   351          __NR_eventfd \n\
   352          __NR_fallocate \n\
   353          __NR_timerfd_settime \n\
   354          __NR_timerfd_gettime \n\
   355          __NR_signalfd4 \n\
   356          __NR_eventfd2 \n\
   357          __NR_epoll_create1 \n\
   358          __NR_dup3 \n\
   359          __NR_pipe2 \n\
   360          __NR_inotify_init1 \n\
   361          __NR_preadv \n\
   362          __NR_pwritev \n\
   363          __NR_rt_tgsigqueueinfo \n\
   364          __NR_perf_event_open \n\
   365          __NR_recvmmsg \n\
   366          __NR_accept4 \n\
   367          __NR_fanotify_init \n\
   368          __NR_fanotify_mark \n\
   369          __NR_prlimit64 \n\
   370          __NR_name_to_handle_at \n\
   371          __NR_open_by_handle_at \n\
   372          __NR_clock_adjtime \n\
   373          __NR_syncfs \n\
   374          __NR_sendmmsg \n\
   375          __NR_setns \n\
   376          __NR_process_vm_readv \n\
   377          __NR_process_vm_writev \n\
   378          __NR_kcmp \n\
   379          __NR_finit_module \n\
   380          __NR_sched_setattr \n\
   381          __NR_sched_getattr \n\
   382          __NR_renameat2 \n\
   383          __NR_seccomp \n\
   384          __NR_getrandom \n\
   385          __NR_memfd_create \n\
   386          __NR_bpf \n\
   387          __NR_execveat \n\
   388          __NR_userfaultfd \n\
   389          __NR_membarrier \n\
   390          __NR_mlock2 \n\
   391          __NR_copy_file_range \n\
   392          __NR_preadv2 \n\
   393          __NR_pwritev2 \n\
   394          __NR_pkey_mprotect \n\
   395          __NR_pkey_alloc \n\
   396          __NR_pkey_free \n\
   397          __NR_statx \n\
"


int main(int argc, char* argv[])
{
	pid_t pid = 0;

	int opt;
	int exId;
	int inId;

	while ((opt = getopt(argc, argv, "p:L:v:e:")) != -1) {		//method in <unistd.h> return int ? switch 'char'
		switch (opt) {
			case 'p':
				pid = strtol(optarg, NULL, 0);
				break;
			case 'L':
				printf(SYSCALLTABLE);
				exit(0);
				break;
			case 'v':
				exId = strtol(optarg, NULL, 0);
				excludeSysCall[exId] = 1;
				break;
			case 'e':
				isInclude = 1;
				inId = strtol(optarg, NULL, 0);
				includeSysCall[inId] = 1;
				break;
			default:
				fprintf(stderr, HELPSTR, argv[0]);
				exit(0);
				break;
		}
	}

	sysCallNameStr[0]  = " __NR_restart_syscall ";
	sysCallNameStr[1]  = " __NR_exit ";
	sysCallNameStr[2]  = " __NR_fork ";
	sysCallNameStr[3]  = " __NR_read ";
	sysCallNameStr[4]  = " __NR_write ";
	sysCallNameStr[5]  = " __NR_open ";
	sysCallNameStr[6]  = " __NR_close ";
	sysCallNameStr[7]  = "";
	sysCallNameStr[8]  = " __NR_creat ";
	sysCallNameStr[9]  = " __NR_link ";
	sysCallNameStr[10]  = " __NR_unlink ";
	sysCallNameStr[11]  = " __NR_execve ";
	sysCallNameStr[12]  = " __NR_chdir ";
	sysCallNameStr[13]  = "";
	sysCallNameStr[14]  = " __NR_mknod ";
	sysCallNameStr[15]  = " __NR_chmod ";
	sysCallNameStr[16]  = " __NR_lchown ";
	sysCallNameStr[17]  = "";
	sysCallNameStr[18]  = "";
	sysCallNameStr[19]  = " __NR_lseek ";
	sysCallNameStr[20]  = " __NR_getpid ";
	sysCallNameStr[21]  = " __NR_mount ";
	sysCallNameStr[22]  = "";
	sysCallNameStr[23]  = " __NR_setuid ";
	sysCallNameStr[24]  = " __NR_getuid ";
	sysCallNameStr[25]  = "";
	sysCallNameStr[26]  = " __NR_ptrace ";
	sysCallNameStr[27]  = "";
	sysCallNameStr[28]  = "";
	sysCallNameStr[29]  = " __NR_pause ";
	sysCallNameStr[30]  = "";
	sysCallNameStr[31]  = "";
	sysCallNameStr[32]  = "";
	sysCallNameStr[33]  = " __NR_access ";
	sysCallNameStr[34]  = " __NR_nice ";
	sysCallNameStr[35]  = "";
	sysCallNameStr[36]  = " __NR_sync ";
	sysCallNameStr[37]  = " __NR_kill ";
	sysCallNameStr[38]  = " __NR_rename ";
	sysCallNameStr[39]  = " __NR_mkdir ";
	sysCallNameStr[40]  = " __NR_rmdir ";
	sysCallNameStr[41]  = " __NR_dup ";
	sysCallNameStr[42]  = " __NR_pipe ";
	sysCallNameStr[43]  = " __NR_times ";
	sysCallNameStr[44]  = "";
	sysCallNameStr[45]  = " __NR_brk ";
	sysCallNameStr[46]  = " __NR_setgid ";
	sysCallNameStr[47]  = " __NR_getgid ";
	sysCallNameStr[48]  = "";
	sysCallNameStr[49]  = " __NR_geteuid ";
	sysCallNameStr[50]  = " __NR_getegid ";
	sysCallNameStr[51]  = " __NR_acct ";
	sysCallNameStr[52]  = " __NR_umount2 ";
	sysCallNameStr[53]  = "";
	sysCallNameStr[54]  = " __NR_ioctl ";
	sysCallNameStr[55]  = " __NR_fcntl ";
	sysCallNameStr[56]  = "";
	sysCallNameStr[57]  = " __NR_setpgid ";
	sysCallNameStr[58]  = "";
	sysCallNameStr[59]  = "";
	sysCallNameStr[60]  = " __NR_umask ";
	sysCallNameStr[61]  = " __NR_chroot ";
	sysCallNameStr[62]  = " __NR_ustat ";
	sysCallNameStr[63]  = " __NR_dup2 ";
	sysCallNameStr[64]  = " __NR_getppid ";
	sysCallNameStr[65]  = " __NR_getpgrp ";
	sysCallNameStr[66]  = " __NR_setsid ";
	sysCallNameStr[67]  = " __NR_sigaction ";
	sysCallNameStr[68]  = "";
	sysCallNameStr[69]  = "";
	sysCallNameStr[70]  = " __NR_setreuid ";
	sysCallNameStr[71]  = " __NR_setregid ";
	sysCallNameStr[72]  = " __NR_sigsuspend ";
	sysCallNameStr[73]  = " __NR_sigpending ";
	sysCallNameStr[74]  = " __NR_sethostname ";
	sysCallNameStr[75]  = " __NR_setrlimit ";
	sysCallNameStr[76]  = "";
	sysCallNameStr[77]  = " __NR_getrusage ";
	sysCallNameStr[78]  = " __NR_gettimeofday ";
	sysCallNameStr[79]  = " __NR_settimeofday ";
	sysCallNameStr[80]  = " __NR_getgroups ";
	sysCallNameStr[81]  = " __NR_setgroups ";
	sysCallNameStr[82]  = "";
	sysCallNameStr[83]  = " __NR_symlink ";
	sysCallNameStr[84]  = "";
	sysCallNameStr[85]  = " __NR_readlink ";
	sysCallNameStr[86]  = " __NR_uselib ";
	sysCallNameStr[87]  = " __NR_swapon ";
	sysCallNameStr[88]  = " __NR_reboot ";
	sysCallNameStr[89]  = "";
	sysCallNameStr[90]  = "";
	sysCallNameStr[91]  = " __NR_munmap ";
	sysCallNameStr[92]  = " __NR_truncate ";
	sysCallNameStr[93]  = " __NR_ftruncate ";
	sysCallNameStr[94]  = " __NR_fchmod ";
	sysCallNameStr[95]  = " __NR_fchown ";
	sysCallNameStr[96]  = " __NR_getpriority ";
	sysCallNameStr[97]  = " __NR_setpriority ";
	sysCallNameStr[98]  = "";
	sysCallNameStr[99]  = " __NR_statfs ";
	sysCallNameStr[100]  = " __NR_fstatfs ";
	sysCallNameStr[101]  = "";
	sysCallNameStr[102]  = "";
	sysCallNameStr[103]  = " __NR_syslog ";
	sysCallNameStr[104]  = " __NR_setitimer ";
	sysCallNameStr[105]  = " __NR_getitimer ";
	sysCallNameStr[106]  = " __NR_stat ";
	sysCallNameStr[107]  = " __NR_lstat ";
	sysCallNameStr[108]  = " __NR_fstat ";
	sysCallNameStr[109]  = "";
	sysCallNameStr[110]  = "";
	sysCallNameStr[111]  = " __NR_vhangup ";
	sysCallNameStr[112]  = "";
	sysCallNameStr[113]  = "";
	sysCallNameStr[114]  = " __NR_wait4 ";
	sysCallNameStr[115]  = " __NR_swapoff ";
	sysCallNameStr[116]  = " __NR_sysinfo ";
	sysCallNameStr[117]  = "";
	sysCallNameStr[118]  = " __NR_fsync ";
	sysCallNameStr[119]  = " __NR_sigreturn ";
	sysCallNameStr[120]  = " __NR_clone ";
	sysCallNameStr[121]  = " __NR_setdomainname ";
	sysCallNameStr[122]  = " __NR_uname ";
	sysCallNameStr[123]  = "";
	sysCallNameStr[124]  = " __NR_adjtimex ";
	sysCallNameStr[125]  = " __NR_mprotect ";
	sysCallNameStr[126]  = " __NR_sigprocmask ";
	sysCallNameStr[127]  = "";
	sysCallNameStr[128]  = " __NR_init_module ";
	sysCallNameStr[129]  = " __NR_delete_module ";
	sysCallNameStr[130]  = "";
	sysCallNameStr[131]  = " __NR_quotactl ";
	sysCallNameStr[132]  = " __NR_getpgid ";
	sysCallNameStr[133]  = " __NR_fchdir ";
	sysCallNameStr[134]  = " __NR_bdflush ";
	sysCallNameStr[135]  = " __NR_sysfs ";
	sysCallNameStr[136]  = " __NR_personality ";
	sysCallNameStr[137]  = "";
	sysCallNameStr[138]  = " __NR_setfsuid ";
	sysCallNameStr[139]  = " __NR_setfsgid ";
	sysCallNameStr[140]  = " __NR__llseek ";
	sysCallNameStr[141]  = " __NR_getdents ";
	sysCallNameStr[142]  = " __NR__newselect ";
	sysCallNameStr[143]  = " __NR_flock ";
	sysCallNameStr[144]  = " __NR_msync ";
	sysCallNameStr[145]  = " __NR_readv ";
	sysCallNameStr[146]  = " __NR_writev ";
	sysCallNameStr[147]  = " __NR_getsid ";
	sysCallNameStr[148]  = " __NR_fdatasync ";
	sysCallNameStr[149]  = " __NR__sysctl ";
	sysCallNameStr[150]  = " __NR_mlock ";
	sysCallNameStr[151]  = " __NR_munlock ";
	sysCallNameStr[152]  = " __NR_mlockall ";
	sysCallNameStr[153]  = " __NR_munlockall ";
	sysCallNameStr[154]  = " __NR_sched_setparam ";
	sysCallNameStr[155]  = " __NR_sched_getparam ";
	sysCallNameStr[156]  = " __NR_sched_setscheduler ";
	sysCallNameStr[157]  = " __NR_sched_getscheduler ";
	sysCallNameStr[158]  = " __NR_sched_yield ";
	sysCallNameStr[159]  = " __NR_sched_get_priority_max ";
	sysCallNameStr[160]  = " __NR_sched_get_priority_min ";
	sysCallNameStr[161]  = " __NR_sched_rr_get_interval ";
	sysCallNameStr[162]  = " __NR_nanosleep ";
	sysCallNameStr[163]  = " __NR_mremap ";
	sysCallNameStr[164]  = " __NR_setresuid ";
	sysCallNameStr[165]  = " __NR_getresuid ";
	sysCallNameStr[166]  = "";
	sysCallNameStr[167]  = "";
	sysCallNameStr[168]  = " __NR_poll ";
	sysCallNameStr[169]  = " __NR_nfsservctl ";
	sysCallNameStr[170]  = " __NR_setresgid ";
	sysCallNameStr[171]  = " __NR_getresgid ";
	sysCallNameStr[172]  = " __NR_prctl ";
	sysCallNameStr[173]  = " __NR_rt_sigreturn ";
	sysCallNameStr[174]  = " __NR_rt_sigaction ";
	sysCallNameStr[175]  = " __NR_rt_sigprocmask ";
	sysCallNameStr[176]  = " __NR_rt_sigpending ";
	sysCallNameStr[177]  = " __NR_rt_sigtimedwait ";
	sysCallNameStr[178]  = " __NR_rt_sigqueueinfo ";
	sysCallNameStr[179]  = " __NR_rt_sigsuspend ";
	sysCallNameStr[180]  = " __NR_pread64 ";
	sysCallNameStr[181]  = " __NR_pwrite64 ";
	sysCallNameStr[182]  = " __NR_chown ";
	sysCallNameStr[183]  = " __NR_getcwd ";
	sysCallNameStr[184]  = " __NR_capget ";
	sysCallNameStr[185]  = " __NR_capset ";
	sysCallNameStr[186]  = " __NR_sigaltstack ";
	sysCallNameStr[187]  = " __NR_sendfile ";
	sysCallNameStr[188]  = "";
	sysCallNameStr[189]  = "";
	sysCallNameStr[190]  = " __NR_vfork ";
	sysCallNameStr[191]  = " __NR_ugetrlimit ";
	sysCallNameStr[192]  = " __NR_mmap2 ";
	sysCallNameStr[193]  = " __NR_truncate64 ";
	sysCallNameStr[194]  = " __NR_ftruncate64 ";
	sysCallNameStr[195]  = " __NR_stat64 ";
	sysCallNameStr[196]  = " __NR_lstat64 ";
	sysCallNameStr[197]  = " __NR_fstat64 ";
	sysCallNameStr[198]  = " __NR_lchown32 ";
	sysCallNameStr[199]  = " __NR_getuid32 ";
	sysCallNameStr[200]  = " __NR_getgid32 ";
	sysCallNameStr[201]  = " __NR_geteuid32 ";
	sysCallNameStr[202]  = " __NR_getegid32 ";
	sysCallNameStr[203]  = " __NR_setreuid32 ";
	sysCallNameStr[204]  = " __NR_setregid32 ";
	sysCallNameStr[205]  = " __NR_getgroups32 ";
	sysCallNameStr[206]  = " __NR_setgroups32 ";
	sysCallNameStr[207]  = " __NR_fchown32 ";
	sysCallNameStr[208]  = " __NR_setresuid32 ";
	sysCallNameStr[209]  = " __NR_getresuid32 ";
	sysCallNameStr[210]  = " __NR_setresgid32 ";
	sysCallNameStr[211]  = " __NR_getresgid32 ";
	sysCallNameStr[212]  = " __NR_chown32 ";
	sysCallNameStr[213]  = " __NR_setuid32 ";
	sysCallNameStr[214]  = " __NR_setgid32 ";
	sysCallNameStr[215]  = " __NR_setfsuid32 ";
	sysCallNameStr[216]  = " __NR_setfsgid32 ";
	sysCallNameStr[217]  = " __NR_getdents64 ";
	sysCallNameStr[218]  = " __NR_pivot_root ";
	sysCallNameStr[219]  = " __NR_mincore ";
	sysCallNameStr[220]  = " __NR_madvise ";
	sysCallNameStr[221]  = " __NR_fcntl64 ";
	sysCallNameStr[222]  = "";
	sysCallNameStr[223]  = "";
	sysCallNameStr[224]  = " __NR_gettid ";
	sysCallNameStr[225]  = " __NR_readahead ";
	sysCallNameStr[226]  = " __NR_setxattr ";
	sysCallNameStr[227]  = " __NR_lsetxattr ";
	sysCallNameStr[228]  = " __NR_fsetxattr ";
	sysCallNameStr[229]  = " __NR_getxattr ";
	sysCallNameStr[230]  = " __NR_lgetxattr ";
	sysCallNameStr[231]  = " __NR_fgetxattr ";
	sysCallNameStr[232]  = " __NR_listxattr ";
	sysCallNameStr[233]  = " __NR_llistxattr ";
	sysCallNameStr[234]  = " __NR_flistxattr ";
	sysCallNameStr[235]  = " __NR_removexattr ";
	sysCallNameStr[236]  = " __NR_lremovexattr ";
	sysCallNameStr[237]  = " __NR_fremovexattr ";
	sysCallNameStr[238]  = " __NR_tkill ";
	sysCallNameStr[239]  = " __NR_sendfile64 ";
	sysCallNameStr[240]  = " __NR_futex ";
	sysCallNameStr[241]  = " __NR_sched_setaffinity ";
	sysCallNameStr[242]  = " __NR_sched_getaffinity ";
	sysCallNameStr[243]  = " __NR_io_setup ";
	sysCallNameStr[244]  = " __NR_io_destroy ";
	sysCallNameStr[245]  = " __NR_io_getevents ";
	sysCallNameStr[246]  = " __NR_io_submit ";
	sysCallNameStr[247]  = " __NR_io_cancel ";
	sysCallNameStr[248]  = " __NR_exit_group ";
	sysCallNameStr[249]  = " __NR_lookup_dcookie ";
	sysCallNameStr[250]  = " __NR_epoll_create ";
	sysCallNameStr[251]  = " __NR_epoll_ctl ";
	sysCallNameStr[252]  = " __NR_epoll_wait ";
	sysCallNameStr[253]  = " __NR_remap_file_pages ";
	sysCallNameStr[254]  = "";
	sysCallNameStr[255]  = "";
	sysCallNameStr[256]  = " __NR_set_tid_address ";
	sysCallNameStr[257]  = " __NR_timer_create ";
	sysCallNameStr[258]  = " __NR_timer_settime ";
	sysCallNameStr[259]  = " __NR_timer_gettime ";
	sysCallNameStr[260]  = " __NR_timer_getoverrun ";
	sysCallNameStr[261]  = " __NR_timer_delete ";
	sysCallNameStr[262]  = " __NR_clock_settime ";
	sysCallNameStr[263]  = " __NR_clock_gettime ";
	sysCallNameStr[264]  = " __NR_clock_getres ";
	sysCallNameStr[265]  = " __NR_clock_nanosleep ";
	sysCallNameStr[266]  = " __NR_statfs64 ";
	sysCallNameStr[267]  = " __NR_fstatfs64 ";
	sysCallNameStr[268]  = " __NR_tgkill ";
	sysCallNameStr[269]  = " __NR_utimes ";
	sysCallNameStr[270]  = " __NR_arm_fadvise64_64 ";
	sysCallNameStr[271]  = " __NR_pciconfig_iobase ";
	sysCallNameStr[272]  = " __NR_pciconfig_read ";
	sysCallNameStr[273]  = " __NR_pciconfig_write ";
	sysCallNameStr[274]  = " __NR_mq_open ";
	sysCallNameStr[275]  = " __NR_mq_unlink ";
	sysCallNameStr[276]  = " __NR_mq_timedsend ";
	sysCallNameStr[277]  = " __NR_mq_timedreceive ";
	sysCallNameStr[278]  = " __NR_mq_notify ";
	sysCallNameStr[279]  = " __NR_mq_getsetattr ";
	sysCallNameStr[280]  = " __NR_waitid ";
	sysCallNameStr[281]  = " __NR_socket ";
	sysCallNameStr[282]  = " __NR_bind ";
	sysCallNameStr[283]  = " __NR_connect ";
	sysCallNameStr[284]  = " __NR_listen ";
	sysCallNameStr[285]  = " __NR_accept ";
	sysCallNameStr[286]  = " __NR_getsockname ";
	sysCallNameStr[287]  = " __NR_getpeername ";
	sysCallNameStr[288]  = " __NR_socketpair ";
	sysCallNameStr[289]  = " __NR_send ";
	sysCallNameStr[290]  = " __NR_sendto ";
	sysCallNameStr[291]  = " __NR_recv ";
	sysCallNameStr[292]  = " __NR_recvfrom ";
	sysCallNameStr[293]  = " __NR_shutdown ";
	sysCallNameStr[294]  = " __NR_setsockopt ";
	sysCallNameStr[295]  = " __NR_getsockopt ";
	sysCallNameStr[296]  = " __NR_sendmsg ";
	sysCallNameStr[297]  = " __NR_recvmsg ";
	sysCallNameStr[298]  = " __NR_semop ";
	sysCallNameStr[299]  = " __NR_semget ";
	sysCallNameStr[300]  = " __NR_semctl ";
	sysCallNameStr[301]  = " __NR_msgsnd ";
	sysCallNameStr[302]  = " __NR_msgrcv ";
	sysCallNameStr[303]  = " __NR_msgget ";
	sysCallNameStr[304]  = " __NR_msgctl ";
	sysCallNameStr[305]  = " __NR_shmat ";
	sysCallNameStr[306]  = " __NR_shmdt ";
	sysCallNameStr[307]  = " __NR_shmget ";
	sysCallNameStr[308]  = " __NR_shmctl ";
	sysCallNameStr[309]  = " __NR_add_key ";
	sysCallNameStr[310]  = " __NR_request_key ";
	sysCallNameStr[311]  = " __NR_keyctl ";
	sysCallNameStr[312]  = " __NR_semtimedop ";
	sysCallNameStr[313]  = " __NR_vserver ";
	sysCallNameStr[314]  = " __NR_ioprio_set ";
	sysCallNameStr[315]  = " __NR_ioprio_get ";
	sysCallNameStr[316]  = " __NR_inotify_init ";
	sysCallNameStr[317]  = " __NR_inotify_add_watch ";
	sysCallNameStr[318]  = " __NR_inotify_rm_watch ";
	sysCallNameStr[319]  = " __NR_mbind ";
	sysCallNameStr[320]  = " __NR_get_mempolicy ";
	sysCallNameStr[321]  = " __NR_set_mempolicy ";
	sysCallNameStr[322]  = " __NR_openat ";
	sysCallNameStr[323]  = " __NR_mkdirat ";
	sysCallNameStr[324]  = " __NR_mknodat ";
	sysCallNameStr[325]  = " __NR_fchownat ";
	sysCallNameStr[326]  = " __NR_futimesat ";
	sysCallNameStr[327]  = " __NR_fstatat64 ";
	sysCallNameStr[328]  = " __NR_unlinkat ";
	sysCallNameStr[329]  = " __NR_renameat ";
	sysCallNameStr[330]  = " __NR_linkat ";
	sysCallNameStr[331]  = " __NR_symlinkat ";
	sysCallNameStr[332]  = " __NR_readlinkat ";
	sysCallNameStr[333]  = " __NR_fchmodat ";
	sysCallNameStr[334]  = " __NR_faccessat ";
	sysCallNameStr[335]  = " __NR_pselect6 ";
	sysCallNameStr[336]  = " __NR_ppoll ";
	sysCallNameStr[337]  = " __NR_unshare ";
	sysCallNameStr[338]  = " __NR_set_robust_list ";
	sysCallNameStr[339]  = " __NR_get_robust_list ";
	sysCallNameStr[340]  = " __NR_splice ";
	sysCallNameStr[341]  = " __NR_arm_sync_file_range ";
	sysCallNameStr[342]  = " __NR_tee ";
	sysCallNameStr[343]  = " __NR_vmsplice ";
	sysCallNameStr[344]  = " __NR_move_pages ";
	sysCallNameStr[345]  = " __NR_getcpu ";
	sysCallNameStr[346]  = " __NR_epoll_pwait ";
	sysCallNameStr[347]  = " __NR_kexec_load ";
	sysCallNameStr[348]  = " __NR_utimensat ";
	sysCallNameStr[349]  = " __NR_signalfd ";
	sysCallNameStr[350]  = " __NR_timerfd_create ";
	sysCallNameStr[351]  = " __NR_eventfd ";
	sysCallNameStr[352]  = " __NR_fallocate ";
	sysCallNameStr[353]  = " __NR_timerfd_settime ";
	sysCallNameStr[354]  = " __NR_timerfd_gettime ";
	sysCallNameStr[355]  = " __NR_signalfd4 ";
	sysCallNameStr[356]  = " __NR_eventfd2 ";
	sysCallNameStr[357]  = " __NR_epoll_create1 ";
	sysCallNameStr[358]  = " __NR_dup3 ";
	sysCallNameStr[359]  = " __NR_pipe2 ";
	sysCallNameStr[360]  = " __NR_inotify_init1 ";
	sysCallNameStr[361]  = " __NR_preadv ";
	sysCallNameStr[362]  = " __NR_pwritev ";
	sysCallNameStr[363]  = " __NR_rt_tgsigqueueinfo ";
	sysCallNameStr[364]  = " __NR_perf_event_open ";
	sysCallNameStr[365]  = " __NR_recvmmsg ";
	sysCallNameStr[366]  = " __NR_accept4 ";
	sysCallNameStr[367]  = " __NR_fanotify_init ";
	sysCallNameStr[368]  = " __NR_fanotify_mark ";
	sysCallNameStr[369]  = " __NR_prlimit64 ";
	sysCallNameStr[370]  = " __NR_name_to_handle_at ";
	sysCallNameStr[371]  = " __NR_open_by_handle_at ";
	sysCallNameStr[372]  = " __NR_clock_adjtime ";
	sysCallNameStr[373]  = " __NR_syncfs ";
	sysCallNameStr[374]  = " __NR_sendmmsg ";
	sysCallNameStr[375]  = " __NR_setns ";
	sysCallNameStr[376]  = " __NR_process_vm_readv ";
	sysCallNameStr[377]  = " __NR_process_vm_writev ";
	sysCallNameStr[378]  = " __NR_kcmp ";
	sysCallNameStr[379]  = " __NR_finit_module ";
	sysCallNameStr[380]  = " __NR_sched_setattr ";
	sysCallNameStr[381]  = " __NR_sched_getattr ";
	sysCallNameStr[382]  = " __NR_renameat2 ";
	sysCallNameStr[383]  = " __NR_seccomp ";
	sysCallNameStr[384]  = " __NR_getrandom ";
	sysCallNameStr[385]  = " __NR_memfd_create ";
	sysCallNameStr[386]  = " __NR_bpf ";
	sysCallNameStr[387]  = " __NR_execveat ";
	sysCallNameStr[388]  = " __NR_userfaultfd ";
	sysCallNameStr[389]  = " __NR_membarrier ";
	sysCallNameStr[390]  = " __NR_mlock2 ";
	sysCallNameStr[391]  = " __NR_copy_file_range ";
	sysCallNameStr[392]  = " __NR_preadv2 ";
	sysCallNameStr[393]  = " __NR_pwritev2 ";
	sysCallNameStr[394]  = " __NR_pkey_mprotect ";
	sysCallNameStr[395]  = " __NR_pkey_alloc ";
	sysCallNameStr[396]  = " __NR_pkey_free ";
	sysCallNameStr[397]  = " __NR_statx ";



	//pid_t traced_process;
	int status;
	//traced_process = atoi(argv[1]);
	if(0 != ptrace(PTRACE_ATTACH, pid, NULL, NULL))
	{
		printf("Trace Process failed: %d\n", errno);
		return 1;
	}
    int intocall = 0^1; //enter SWI
    //int intocall = 0; // out SWI
	while(1)
	{
		wait(&status);
		if(WIFEXITED(status))
		{
			break;
		}
        if(intocall)
		    tracePro(pid);
        intocall ^= 1;
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

	}
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	return 0;
}
