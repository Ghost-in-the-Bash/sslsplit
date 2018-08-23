#ifndef NETGROK_H
#define NETGROK_H

#include "log.h"
#include "logbuf.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef struct connection connection_t;

// log.h: typedef struct log_content_ctx log_content_ctx_t;
// logbuf.h: struct logbuf; typedef struct logbuf logbuf_t;

int netgrok(log_content_ctx_t *ctx, logbuf_t *lb);
void readFilename(char *filepath, connection_t *session);
void readHeaders(unsigned char *buf, ssize_t bufsize, connection_t *session);
int areSameStrings(const char *lhs, const char *rhs, int len);
void readAddresses(connection_t *session);
void printSession(connection_t *session);

#endif /* NETGROK_H */
