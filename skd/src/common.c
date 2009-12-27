#include <sys/signal.h>
#include <sys/wait.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>

#include "../include/common.h"
#include "../include/config.h"

// Debug function
//__inline__ void debug(char * format, ...){


void sig_child(int n) {
    signal(SIGCHLD, sig_child);
    waitpid(-1, NULL, WNOHANG);
}

inline int max(int a, int b) {
    return a > b ? a : b;
}

unsigned long resolve(const char *host, char *ip) {
    struct hostent *he;
    struct sockaddr_in si;

    he = gethostbyname(host);
    if (!he) {
        return INADDR_NONE;
    }
    memcpy((char *) &si.sin_addr, (char *) he->h_addr, sizeof(si.sin_addr));
    if (ip) strcpy(ip, inet_ntoa(si.sin_addr));
    return si.sin_addr.s_addr;
}

