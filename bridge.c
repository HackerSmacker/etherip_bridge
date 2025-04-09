/* A simple DECnet bridge program
 * (c) 2003, 2005, 2020 by Johnny Billquist
 *
 * Version 2.5 Change code to make use of more modern pcap interface.
 * Version 2.4 T. DeBellis, minor fixes to keep Xcode on Mac OSX from
 *             complaining, also complaints from gcc 8.3.  Parse for
 *             verbose flags, but force them on if DEBUG set.
 *             Some code pretty printing.
 * Version 2.3 Bugfix. Ports are *unsigned* shorts...
 *             Also added -Wall, and cleaned up some warnings.
 * Version 2.2 Some cleanup, bugfixes and general improvements.
 * Version 2.1 Fixed code for OpenBSD and FreeBSD as well.
 * Version 2.0 (I had to start using a version number sometime, and
 *              since I don't have any clue to the history of my
 *              development here, I just picked 2.0 because I liked
 *              it.)
 * Some more text will come here later.
 */

/* Swift (xcode) preprocessor provides DEBUG

#define DEBUG 0
*/

#ifndef DPORT
#define DPORT 97 /* Allow option to override */
#endif

#define MAX_HOST 32

#define CONF_FILE "bridge.conf"

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#ifdef linux
#include <pcap-bpf.h>
#else
#include <net/bpf.h>
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pcap.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifdef DEBUG                /* if Debugging */
static int Verbose = 1;     /* Then always typing */
static int VeryVerbose = 1; /* Lots of stuff! */
#else                       /* Otherwise, let option decide */
static int Verbose = 0;     /* Then always typing */
static int VeryVerbose = 0; /* Lots of stuff! */
#endif

/* Throttling control:
 * THROTTLETIME - (mS)
 *                If packets come closer in time than this, they are
 *                a base for perhaps considering throttling.
 * THROTTLEPKT  - (#)
 *                The number of packets in sequence that fulfill
 *                THROTTLETIME that means throttling will kick in.
 * THROTTLEDELAY - (uS)
 *                The delay to insert when throttling is active.
 *
 * Passive connection control:
 * PASSIVE_TMO - (mS)
 *               If nothing has been received from a passive node
 *               in this time, sending to it will stop.
 */

#define THROTTLETIME 5
#define THROTTLEPKT 4
#define THROTTLEDELAY 10000

#define PASSIVE_TMO 180000L

#define THROTTLEMASK ((1 << THROTTLEPKT) - 1)

#define ETHERTYPE_DECnet 0x6003
#define ETHERTYPE_LAT 0x6004
#define ETHERTYPE_IPXII 0x8137
#define ETHERTYPE_IPXRAW 0x8137
#define ETHERTYPE_MOPDL 0x6001
#define ETHERTYPE_MOPRC 0x6002
#define ETHERTYPE_LOOPBACK 0x9000

/* xcode (Swift) has MAX (poorly documented), so conditionally define.
 */

#ifndef MAX
#define MAX(a, b) (a > b ? a : b)
#endif

/* This is a very simple and small program for bpf that just
   filters out anything by any protocol that we *know* we're
   not interested in.
 */

struct bpf_insn insns[] = {
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPXRAW, 7, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPXII, 6, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_LOOPBACK, 5, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_MOPRC, 4, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_MOPDL, 3, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_LAT, 2, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_DECnet, 1, 0),
    BPF_STMT(BPF_RET + BPF_K, 0),
    BPF_STMT(BPF_RET + BPF_K, 1518),
};

/* The structures and other global data we keep info in.
   It would perhaps be nice if we could reload this, and
   in case of failure keep the old stuff, but for now we
   don't care that much... */

/* The data structures we have are the port, which describe
   a source/destination for data. It also holds info about which
   kind of traffic should be forwarded to this site. It is also
   used to filter incoming packets. If we don't send something, we
   don't want it from that side either.
   We have the host table, which is a hash table for all known
   destinations, so that we can optimize the traffic a bit.

   When data arrives, we filter, process and send it out again.
 */

#define HDRLEN 14 /* Length of the ethernet header */
#define MAXMEM 8  /* Number of old packets we "remember" */

typedef enum { Unknown, IPXRAW, IPXII, DECnet, LAT, MAXTYP } pkttyp;

struct BRIDGE {
  char name[40];
  char host[80];
  struct in_addr addr;
  unsigned short port;
  int passive;
  int anyport;
  int fd;
  int types[MAXTYP];
  char last[MAXMEM][HDRLEN];
  int lastptr;
  int rcount;
  int dcount;
  int tcount;
  int xcount;
  int zcount;
  struct timeval lasttime;
  int throttle;
  int throttlecount;
  struct timeval lastrcv;
  pcap_t *pcap;
};

struct DATA {
  int source;
  pkttyp type;
  ssize_t len; /* xcode wants limits.h type */
  const unsigned char *data;
};

struct HOST {
  struct HOST *next;
  unsigned char mac[6];
  int bridge;
};

#define HOST_HASH 65536

struct HOST *hosts[HOST_HASH];
struct BRIDGE bridge[MAX_HOST];
int bcnt = 0;
int sd;

char *config_filename;

/* Here comes the code... */

/* lookup
   Based on a sockaddr_in, find the corresponding bridge entry.
   Returns the index of the bridge, or -1 if no match. */
int lookup(struct sockaddr_in *sa) {
  int i;

  for (i = 0; i < bcnt; i++) {
    if ((bridge[i].addr.s_addr == sa->sin_addr.s_addr)
        || bridge[i].anyport) {
      bridge[i].port = sa->sin_port;
      return i;
    }
  }
  return -1;
}

/* lookup_bridge
   Based on a string, find the corresponding bridge.
   Returns bridge index, or -1 if no match.
*/
int lookup_bridge(char *newbridge) {
  int i;
  size_t l = strlen(newbridge); /* Xcode wants limits.h */

  if (Verbose) printf("Trying to match %s\n", newbridge);

  for (i = 0; i < bcnt; i++) {
    if (Verbose) printf("Matching against: %s\n", bridge[i].name);

    if ((strcmp(newbridge, bridge[i].name) == 0) &&
        (l == strlen(bridge[i].name))) {
      if (Verbose) printf("Found match: %s == %s\n", newbridge, bridge[i].name);
      return i;
    }
  }

  if (Verbose) printf("No match found\n");

  return -1;
}

/* add_bridge
   Adds a new bridge entry to the list of bridges
*/
void add_bridge(char *name, char *dst) {
  struct hostent *he;
  char rhost[40];
  int port = 0;
  int i, found = 0;
  in_addr_t addr = 0;
  char *p;
  int passive = 0; /* Keeps xcode from whining */
  int anyport = 0; /* Ditto */

  if (bcnt < MAX_HOST) {
    bzero(&bridge[bcnt], sizeof(struct BRIDGE));
    if (*name == '~') {
      passive = 1;
      name++;
    }
    if (*name == '*') {
      anyport = 1;
      name++;
    }

    strcpy(bridge[bcnt].name, name);
    p = index(dst, ':');
    if (p == NULL) { /* Assume local descriptor */
      struct bpf_program pgm;
      char ebuf[PCAP_ERRBUF_SIZE];

      ebuf[0] = 0;
      if ((bridge[bcnt].pcap = pcap_create(dst, ebuf)) == NULL) {
        printf("Error opening device.\n%s\n", ebuf);
        exit(1);
      }

      if (ebuf[0]) printf("warning: %s\n", ebuf);

      pcap_set_promisc(bridge[bcnt].pcap, 1);
      pcap_set_immediate_mode(bridge[bcnt].pcap, 1);
      pcap_activate(bridge[bcnt].pcap);

      pgm.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
      pgm.bf_insns = insns;

      if (pcap_setfilter(bridge[bcnt].pcap, &pgm) < 0) {
        pcap_perror(bridge[bcnt].pcap, "loading filter program");
        exit(1);
      }

#if 0
      pcap_setnonblock(bridge[bcnt].pcap, 1, ebuf);
      pcap_setdirection(bridge[bcnt].pcap, PCAP_D_IN);
#endif

      strcpy(bridge[bcnt].host, dst);
      bridge[bcnt].addr.s_addr = 0;
      bridge[bcnt].port = 0;
      bridge[bcnt].fd = pcap_get_selectable_fd(bridge[bcnt].pcap);
      if (bridge[bcnt].fd == -1) {
        perror("fd");
        exit(1);
      }

      found = -1;
    } else {
      *p = ' ';
      sscanf(dst, "%s %d", rhost, &port);
      if ((he = gethostbyname(rhost)) != NULL) {
        addr = *(in_addr_t *)he->h_addr;
        found = -1;
      } else {
        found = inet_aton(rhost, (struct in_addr *)&addr);
      }
      if (found) {
        strcpy(bridge[bcnt].host, rhost);
        bridge[bcnt].addr.s_addr = addr;
        bridge[bcnt].port = htons(port);
        bridge[bcnt].fd = sd;
      }
    }
    if (found) {
      for (i = 0; i < MAXTYP; i++) bridge[bcnt].types[i] = 0;

      bridge[bcnt].rcount = 0;
      bridge[bcnt].dcount = 0;
      bridge[bcnt].tcount = 0;
      bridge[bcnt].zcount = 0;
      bridge[bcnt].passive = passive;
      bridge[bcnt].anyport = anyport;

      bcnt++;
      if (Verbose) printf("Adding router ''%s''. %08x:%d\n", name, addr, port);
    }
  } else {
    printf("Warning. Bridge table full. Not adding %s (%s)\n", name, dst);
  }
}

/* add_service
   Adds a servie to a named bridge.
   Services are different protocols.
*/
int add_service(char *newbridge, pkttyp type, char *name) {
  int i;

  if (Verbose) printf("Adding %s bridge %s.\n", name, newbridge);

  if ((i = lookup_bridge(newbridge)) >= 0) {
    if (bridge[i].types[type]++ > 0) {
      printf("%s bridge %s added multiple times.\n", name, newbridge);
    }
    return 1;
  }
  return 0;
}

/* read_conf
   Read the config file
*/
void read_conf(int x) {
  FILE *f;
  int mode = 0;
  int line;
  char buf[80];
  char buf1[40], buf2[40];
  int i;

  if ((f = fopen(config_filename, "r")) == NULL) {
    perror("opening bridge.conf");
    exit(1);
  }

  for (i = 0; i < bcnt; i++) {
    if (bridge[i].fd != sd) close(bridge[i].fd);
  }
  bcnt = 0;

  for (i = 0; i < HOST_HASH; i++) {
    struct HOST *h, *n;
    h = hosts[i];
    hosts[i] = NULL;
    while (h) {
      n = h->next;
      free(h);
      h = n;
    }
  }

  line = 0;
  while (!feof(f)) {
    if (fgets(buf, 80, f) == NULL) continue;
    buf[strlen(buf) - 1] = 0;
    line++;
    if ((strlen(buf) > 2) && (buf[0] != '!')) {
      if (buf[0] == '[') {
        mode = -1;
        if (strcmp(buf, "[bridge]") == 0) mode = 0;
        if (strcmp(buf, "[decnet]") == 0) mode = 1;
        if (strcmp(buf, "[lat]") == 0) mode = 2;
        if (strcmp(buf, "[ipxii]") == 0) mode = 3;
        if (strcmp(buf, "[ipxraw]") == 0) mode = 4;
#if 0
        if(sscanf(buf,"[source %d.%d]", &area, &node) == 2) mode = 3;
        if(strcmp(buf,"[relay]") == 0) mode = 4;
#endif
        if (mode < 0) {
          printf("Bad configuration at line %d\n%s\n", line, buf);
          exit(1);
        }
      } else {
        switch (mode) {
          case 0:
            if (sscanf(buf, "%s %s", buf1, buf2) == 2) {
              add_bridge(buf1, buf2);
            } else {
              printf("Bad bridge at line %d\n%s\n", line, buf);
              exit(1);
            }
            break;
          case 1:
            if (!add_service(buf, DECnet, "DECnet"))
              printf("%d: DECnet bridge %s don't exist.\n", line, buf);
            break;
          case 2:
            if (!add_service(buf, LAT, "LAT"))
              printf("%d: LAT bridge %s don't exist.\n", line, buf);
            break;
          case 3:
            if (!add_service(buf, IPXII, "IPXII"))
              printf("%d: IPXII bridge %s don't exist.\n", line, buf);
            break;
          case 4:
            if (!add_service(buf, IPXRAW, "IPXRAW"))
              printf("%d: IPXRAW bridge %s don't exist.\n", line, buf);
            break;
          default:
            printf("weird state at line %d\n", line);
            exit(1);
        }
      }
    }
  }
  fclose(f);
}

/* is_ethertype
   Check if an ethernet packet have a specific ethernet type
   Returns true if so
*/
int is_ethertype(struct DATA *d, unsigned short type) {
  unsigned char x[2];
  x[0] = (type >> 8);
  x[1] = (type & 255); /* Yuck, but this makes it byte-order safe */
  if(Verbose) printf("EtherType is %02x%02x\n", d->data[12], d->data[13]);
  return ((d->data[13] == x[1]) && (d->data[12] == x[0]));
}


/* is_ipxii
   Returns true if a packet is of type IPX Ethernet II
*/
int is_ipxii(struct DATA *data) {
  return is_ethertype(data, ETHERTYPE_IPXII);
}

/* is_ipxraw
   Returns true if a packet is of type IPX Raw 802.3
*/
int is_ipxraw(struct DATA *data) {
  return is_ethertype(data, ETHERTYPE_IPXRAW);
}

/* is_decnet
   Returns true if a packet is of type DECnet
*/
int is_decnet(struct DATA *data) {
  return is_ethertype(data, ETHERTYPE_DECnet);
}

/* is_lat
   Returns true if a packet is of type LAT, any MOP protocol
   or the loopback protocol.
*/
int is_lat(struct DATA *data) {
  return (is_ethertype(data, ETHERTYPE_LAT) ||
          is_ethertype(data, ETHERTYPE_MOPDL) ||
          is_ethertype(data, ETHERTYPE_MOPRC) ||
          is_ethertype(data, ETHERTYPE_LOOPBACK));
}

/* timedelta
   Return the time from a previous timestamp to current time.
*/
unsigned long timedelta(struct timeval old) {
  struct timeval now;
  unsigned long delta;
  gettimeofday(&now, NULL);
  delta = now.tv_sec - old.tv_sec;
  delta *= 1000;
  delta += ((now.tv_usec - old.tv_usec) / 1000);
  return delta;
}

/* throttle
   Will pause the execution for the THROTTLEDELAYIME if
   the bridge destination have too many packets within
   a short timeframe to trigger the throtteling mechanism.
*/
void throttle(int index) {
  unsigned long delta;

  delta = timedelta(bridge[index].lasttime);
  bridge[index].throttle <<= 1;
  bridge[index].throttle += (delta < THROTTLETIME ? 1 : 0);

  if ((bridge[index].throttle & THROTTLEMASK) == THROTTLEMASK) {
    bridge[index].throttlecount++;
    usleep(THROTTLEDELAY);
  }
  gettimeofday(&bridge[index].lasttime, NULL);
}

/* active
   Checks if a bridge is active or not.
*/
int active(int index) {
  if (bridge[index].passive == 0) return 1;
  if (timedelta(bridge[index].lastrcv) < PASSIVE_TMO) return 1;
  return 0;
}

/* send_packet
   Send an ethernet packet to a specific bridge.
*/
void send_packet(int index, struct DATA *d) {
  struct sockaddr_in sa;

  if (index == d->source) return; /* Avoid loopback of data. */
  if (bridge[index].types[d->type] == 0)
    return; /* Avoid sending unwanted frames */

  if (active(index)) {
    bridge[index].tcount++;
    throttle(index);

    if (bridge[index].addr.s_addr == 0) {
      if(Verbose) printf("pcap_injecting length %d\n", d->len);
      if(Verbose) printf("sent ethertype is %02x%02x\n", d->data[12], d->data[13]);
      if (pcap_inject(bridge[index].pcap, d->data, d->len) == -1)
        perror("Error local network write"); /* Say something, but carry on */
      if(Verbose) printf("packet written\n");

    } else {
      unsigned char *outbuf = malloc(d->len + 2);
      outbuf[0] = 0x30;
      outbuf[1] = 0x00;
      memcpy(outbuf + 2, d->data, d->len);
      sa.sin_family = AF_INET; /* Remote network. */
      sa.sin_port = bridge[index].port;
      sa.sin_addr.s_addr = bridge[index].addr.s_addr;
      /* if(Verbose) printf("sendto'ing data to %s proto %d len %d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), d->len - 2); */
      if(sendto(bridge[index].fd, outbuf, d->len + 2, 0,
                 (struct sockaddr *)&sa, sizeof(sa)) == -1)
        perror("sendto");
      free(outbuf);
    }

    bridge[index].lastptr++;
    if (bridge[index].lastptr == MAXMEM) bridge[index].lastptr = 0;

    memcpy(bridge[index].last[bridge[index].lastptr], d->data, HDRLEN);
  }
}

/* Register a source MAC address in the hash for fast lookup later.
 * The hash is actually just the two low bytes of the MAC address,
 * which also reflects the DECnet address, so apart from non-DECnet
 * addresses, this hash is very unique.
 *
 * If the hash entry already exists we do nothing.
 * The hash stores which bridge link the source address
 * has been seen on.
 */
void register_source(struct DATA *d) {
  unsigned short hash;
  struct HOST *h;

  hash = *(unsigned short *)(d->data + 10);
  h = hosts[hash];
  while (h) {
    if (memcmp(h->mac, d->data + 6, 6) == 0) {
      h->bridge = d->source;

      if (VeryVerbose)
        printf("Setting existing hash to bridge %d\n", h->bridge);
      return;
    }
    h = h->next;
  }
  h = malloc(sizeof(struct HOST));
  h->next = hosts[hash];
  hosts[hash] = h;
  memcpy(h->mac, d->data + 6, 6);
  h->bridge = d->source;
  if (Verbose) printf("Adding new hash entry. Port is %d\n", h->bridge);
}

/* Locate destination for a data packet.
 * If it is a multicast, we return -1, to indicate it should be sent
 * to all destination.
 * Otherwise we try to find the destination in our hash.
 * If that succeeds, we have a destination link to use.
 * If the MAC does not exist in the hash, we fall back to transmitting
 * to all destinations.
 */
int locate_dest(struct DATA *d) {
  unsigned short hash;
  struct HOST *h;

  if (d->data[0] & 1) return -1; /* Ethernet multicast */

  hash = *(unsigned short *)(d->data + 4);
  h = hosts[hash];
  while (h) {
    if (memcmp(h->mac, d->data, 6) == 0) return h->bridge;
    h = h->next;
  }
  return -1;
}

/* Figure out what type a packet is.
 */
pkttyp classify_packet(struct DATA *d) {
  if (is_ipxii(d)) return IPXII;
  if (is_ipxraw(d)) return IPXRAW;
  if (is_decnet(d)) return DECnet;
  if (is_lat(d)) return LAT;

  return Unknown;
}

void dump_nomatch(struct sockaddr_in *r, struct DATA *d) {
  if (Verbose)
    printf("Dumped packet from %s (%d).\n", inet_ntoa(r->sin_addr),
           ntohs(r->sin_port));
}

/* Process a packet.
 * This is called after a packet is received, and
 * if the same packet was recently sent out on the
 * same interface, this packet is dropped.
 * If the type is acceptable from the source, it is
 * forwarded to the correct destination.
 */
void process_packet(struct DATA *d) {
  int dst;
  int i;

  bridge[d->source].zcount++;
  if(Verbose) printf("current zcount for d->source %d is %d\n", d->source, bridge[d->source].zcount);
  d->type = classify_packet(d);
  if(Verbose) printf("classified packet type is %d\n", d->type);

  if (d->type == Unknown) {
    if(Verbose) puts("packet type is unknown!");
    bridge[d->source].dcount++;
    return;
  }
  if (bridge[d->source].types[d->type] == 0) {
    if(Verbose) printf("(1) dcount for interface is now %d\n", bridge[d->source].dcount++);
    bridge[d->source].dcount++;
    return;
  }


  bridge[d->source].rcount++;
    if(Verbose) printf("rcount for interface is now %d\n", bridge[d->source].rcount++);
  for (i = 0; i < MAXMEM; i++) {
    if (memcmp(bridge[d->source].last[i], d->data, HDRLEN) == 0) {
      bridge[d->source].dcount++;
      if(Verbose) printf("(2) dcount for interface is now %d\n", bridge[d->source].dcount++);
      return;
    }
  }

  gettimeofday(&bridge[d->source].lastrcv, NULL);
  bridge[d->source].xcount++;
  if(Verbose) printf("xcount for interface is now %d\n", bridge[d->source].xcount++);
  
  register_source(d);
  dst = locate_dest(d);
  if(Verbose) printf("dest ID is %d\n", dst);
  if (dst == -1) {
    int i;
    for (i = 0; i < bcnt; i++) send_packet(i, d);
  } else {
    send_packet(dst, d);
  }
}

void dump_data() {
  int i;

  printf("Host table:\n");
  for (i = 0; i < bcnt; i++)
    printf(
        "%d: %s %s:%d (Rx: %d(%d) Tx: %d Fw: %d (Drop rx: %d)) Active: %d "
        "Throttle: %d(%03o)\n",
        i, bridge[i].name, inet_ntoa(bridge[i].addr), ntohs(bridge[i].port),
        bridge[i].rcount, bridge[i].zcount, bridge[i].tcount, bridge[i].xcount,
        bridge[i].dcount, active(i), bridge[i].throttlecount,
        bridge[i].throttle & 255);
  printf("Hash of known destinations:\n");
  for (i = 0; i < HOST_HASH; i++) {
    struct HOST *h;
    h = hosts[i];
    while (h) {
      printf("%02x%02x%02x%02x%02x%02x -> %d", (unsigned char)h->mac[0],
             (unsigned char)h->mac[1], (unsigned char)h->mac[2],
             (unsigned char)h->mac[3], (unsigned char)h->mac[4],
             (unsigned char)h->mac[5], h->bridge);
      if ((unsigned char)h->mac[0] == 0xaa &&
          (unsigned char)h->mac[1] == 0x00 &&
          (unsigned char)h->mac[2] == 0x04 &&
          (unsigned char)h->mac[3] == 0x00) {
        printf(" (%d.%d)", h->mac[5] >> 2, ((h->mac[5] & 3) << 8) + h->mac[4]);
      }
      printf("\n");
      h = h->next;
    }
  }
}

int main(int argc, char **argv) {
  struct sockaddr_in sa, rsa;
  int i, hsock, ch;
  fd_set fds;
  socklen_t ilen;
  int port = 0;
  struct DATA d;
  unsigned char buf[8192];

  signal(SIGHUP, read_conf);
  signal(SIGUSR1, dump_data);

  config_filename = CONF_FILE;

  while ((ch = getopt(argc, argv, "d:p:hvV")) != -1) {
    switch (ch) {
      case 'd':
        config_filename =
            malloc((int)strlen(CONF_FILE) + (int)strlen(optarg) + 2);
        sprintf(config_filename, "%s/%s", optarg, CONF_FILE);
        break;
      case ':':
      case 'p':
        printf("d: %s\n", optarg);
        port = atoi(optarg);
        break;
      case 'v':
        Verbose = 1;
        VeryVerbose = 0;
        break;
      case 'V':
        Verbose = 1;
        VeryVerbose = 1;
        break;

      case '?':
      case 'h':
      default:
        printf(
            "usage: %s [-p <listen protocol number>] [-d <dir>] -v -V "
            "[<port>]\n",
            argv[0]);
        exit(1);
    }
  }

  argc -= optind;
  argv += optind;

  if (argc > 0) {
    if (port) {
      printf("Error: port already set\n");
      exit(1);
    }
    port = atoi(argv[0]);
  }

#if DPORT
  if (port == 0) port = DPORT;
#endif

  if (port == 0) {
    printf("no port given\n");
    exit(1);
  }

  if (VeryVerbose) {
    printf("Printing all debugging messages\n");
  } else {
    if (Verbose) printf("Printing most debugging messages\n");
  }

  if (Verbose) printf("Config filename: %s\n", config_filename);

  if ((sd = socket(PF_INET, SOCK_RAW, port)) == -1) {
    fprintf(stderr, "Could not create raw socket, do you have permission?\n");
    perror("socket");
    exit(1);
  }

  sa.sin_family = AF_INET;
  sa.sin_port = 0;
  sa.sin_addr.s_addr = INADDR_ANY;
  if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
    perror("bind");
    exit(1);
  }

  read_conf(0);

  if (Verbose) dump_data();

  while (1) {
    FD_ZERO(&fds);
    hsock = 0;
    for (i = 0; i < bcnt; i++) {
      FD_SET(bridge[i].fd, &fds);
      if (bridge[i].fd > hsock) hsock = bridge[i].fd;
    }

    if (select(hsock + 1, &fds, NULL, NULL, NULL) == -1) {
      if (errno != EINTR) {
        perror("select");
        exit(1);
      }
      continue;
    }

    for (i = 0; i < bcnt; i++) {
      if (FD_ISSET(bridge[i].fd, &fds)) {
        d.source = i;
        if (bridge[i].addr.s_addr == 0) {
          struct pcap_pkthdr h;
          d.data = pcap_next(bridge[i].pcap, &h);
          if (d.data) {
            d.len = h.caplen;
            process_packet(&d);
          }
        } else {
          ilen = sizeof(rsa);
          if ((d.len = recvfrom(bridge[i].fd, buf, 1522, 0,
                                (struct sockaddr *)&rsa, &ilen)) > 0) {
		    if(Verbose) printf("got something! len = %d\n", d.len);
            d.data = buf + 22;
            if ((d.source = lookup(&rsa)) >= 0) {
		      if(Verbose) printf("d.source %d lookup matched, processing now\n", d.source);
              process_packet(&d); 
            } else {
              dump_nomatch(&rsa, &d);
            }
          }
        }
        FD_CLR(bridge[i].fd, &fds);
      }
    }
  }
}
