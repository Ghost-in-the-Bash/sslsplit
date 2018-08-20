#ifndef NETGROK_H
#define NETGROK_H

#include <stdio.h>
#include <string.h>
#include <wctype.h>

#define PROTOCOL_NAME_MAX_LEN 12
#define IP_MAX_LEN 39
#define PORT_MAX_LEN 6
#define HOST_MAX_LEN 64
#define URL_MAX_LEN 2048

#define HEADERS_ENUMERATED 4
#define LINE_MAX_LEN 4096
#define JSON_MAX_SIZE 7

enum protocol_t {
	SSL,
	TCP,
	HTTP,
	HTTPS
};

enum {
	SSL_HEADER = 0,
	TCP_HEADER = 1,
	HOST_HEADER = 2,
	REFERER_HEADER = 3
};

enum {
	PROTOCOL_INDEX = 0,
	SRC_IP_INDEX = 1,
	SRC_PORT_INDEX = 2,
	DST_IP_INDEX = 3,
	DST_PORT_INDEX = 4,
	HOST_INDEX = 5,
	REFERER_INDEX = 6
};

typedef struct connection {
	char protocol[PROTOCOL_NAME_MAX_LEN];
	char src_ip[IP_MAX_LEN];
	char src_port[PORT_MAX_LEN];
	char dst_ip[IP_MAX_LEN];
	char dst_port[PORT_MAX_LEN];
	char host[HOST_MAX_LEN];
	char referer[URL_MAX_LEN];
} connection;

ssize_t netgrok(unsigned char *buf, ssize_t len);
int same_strings(const char *lhs, const char *rhs, size_t count);
void read_addresses(connection *session);
void print_session(connection *session);

#endif /* NETGROK_H */
