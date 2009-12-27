#ifndef RAW_H
#define RAW_h

//#include "common.h"

struct rawsock {
    unsigned short dport;
    unsigned short sport;
    unsigned long host;
    int r[2];
    int w[2];
	int pid;
};

// Functions
struct rawsock *create_rawsock_session(struct rawsock *r_v, unsigned long ip, int sport, int dport);
struct rawsock *find_rawsock_session(struct rawsock *r_v, unsigned long ip, short sport, short dport);
void destroy_rawsock_session(struct rawsock *r);
void fill_rawsock_session(struct rawsock *r, unsigned char *data, int size);
void stop_rawsock_partner(struct rawsock *r, unsigned char * pass);
void send_rawsock_action(struct rawsock *r, int action, char *file, unsigned char *clientauth);
int start_rawsock_serverd(struct rawsock *r);
int start_rawsock_clientd(struct rawsock *r, unsigned char *clientauth, unsigned char *serverauth);

#endif
