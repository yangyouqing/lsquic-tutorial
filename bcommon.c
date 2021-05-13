// add by yangyouqing
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#ifdef WIN32
#include <Ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "bcommon.h"

char* bp2p_common_parse_addr (const struct sockaddr *addr_sa, char *str_addr, int max_len)
{

    uint32_t ip_version, srcport, dstport;
    struct sockaddr_in  *peer4;
    struct sockaddr_in6 *peer6;
    char dstip[MAX_IP_ADDR_LEN];
    if (!addr_sa)
        return str_addr;

    if (addr_sa->sa_family == AF_INET)
    {
        ip_version = 4;
        peer4 = (struct sockaddr_in *)addr_sa;
        dstport = ntohs(peer4->sin_port);
        inet_ntop(peer4->sin_family, &peer4->sin_addr, dstip, MAX_IP_ADDR_LEN);
    }
    else if (addr_sa->sa_family == AF_INET6)
    {
        ip_version = 6;
        peer6 = (struct sockaddr_in6 *)addr_sa;
        dstport = ntohs(peer6->sin6_port);
        inet_ntop(peer6->sin6_family, &peer6->sin6_addr, dstip, MAX_IP_ADDR_LEN);

    }
    else
        return str_addr;
    snprintf(str_addr, max_len, "%s:%u", dstip, dstport);

    return str_addr;

}
