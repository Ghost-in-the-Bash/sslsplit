#ifndef NETGROK_H
#define NETGROK_H

#include <zmq.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <assert.h>
#include <signal.h>

#define LINE_MAX_LEN 4096
#define IP_STR_MAX_LEN 40 // ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff.
#define INT_STR_MAX_LEN 6 // 65535.
#define PROTOCOL_MAX_LEN 12
#define HOST_MAX_LEN 64
#define REFERER_MAX_LEN 2048
#define TIME_STR_LEN 20
#define TIME_FORMAT "%Y-%m-%d %H:%M:%S" // yyyy-mm-dd HH:mm:ss.
typedef struct connection conn_t;

int netgrok(void *connection_context, unsigned char *content);

int recordTime(char *time_str);

int readHeaders(unsigned char *buf, ssize_t bufsize, conn_t *connection);
int areSameStrings(const char *lhs, const char *rhs, int len);

int getJsonStr(conn_t *connection, char *json_str);
int addToJsonStr(char *name, char *value, char *json_str);

int publish(char *buf, int len);
void interruptHandler(int sig);

#endif /* NETGROK_H */
