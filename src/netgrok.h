#ifndef NETGROK_H
#define NETGROK_H

#include "log.h"
#include "logbuf.h"

#include <zmq.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <signal.h>

typedef struct connection connection_t;

// log.h: typedef struct log_content_ctx log_content_ctx_t;
// logbuf.h: struct logbuf; typedef struct logbuf logbuf_t;

int netgrok(log_content_ctx_t *ctx, logbuf_t *lb);

void readAddresses(char *filepath, connection_t *session);
void interpretProtocol(connection_t *session);
void readHeaders(unsigned char *buf, ssize_t bufsize, connection_t *session);
int areSameStrings(const char *lhs, const char *rhs, int len);
void sessToJSON(connection_t *session, char *buf);

int publish(char *buf, int len);
void interruptHandler(int sig);

#endif /* NETGROK_H */
