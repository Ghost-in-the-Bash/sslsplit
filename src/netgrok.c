/*
The netgrok() function takes input passed in from log_content_submit() in log.c,
which has also been modified to not produce content logs. The netgrok() function
then outputs a JSON dump of connection information to standard output.
*/

#include "netgrok.h"

// definitions
/* -------------------------------------------------------------------------- */
// struct that stores details about each connection
/* -------------------------------------------------------------------------- */
#define CONNECTION_SIZE 8
enum {
	SRC_IP = 0, SRC_PORT = 1, DST_IP = 2, DST_PORT = 3,
	BYTES = 4, PROTOCOL = 5, HOST = 6, REFERER = 7
};
#define IP_MAX_LEN 40
#define INT_MAX_LEN 6
#define PROTOCOL_MAX_LEN 12
#define HOST_MAX_LEN 64
#define REFERER_MAX_LEN 2048
// netgrok.h: typedef struct connection connection_t;
struct connection {
	char src_ip[IP_MAX_LEN]; char src_port[INT_MAX_LEN];
	char dst_ip[IP_MAX_LEN]; char dst_port[INT_MAX_LEN];
	char bytes[INT_MAX_LEN]; char protocol[PROTOCOL_MAX_LEN];
	char host[HOST_MAX_LEN]; char referer[REFERER_MAX_LEN];
};
/* -------------------------------------------------------------------------- */

// headers that netgrok() looks for in connection content
/* -------------------------------------------------------------------------- */
#define HEADERS_TOTAL 2
enum {HOST_HEADER = 0, REFERER_HEADER = 1};
static const char *headers[HEADERS_TOTAL] = {"host:", "referer:"};
/* -------------------------------------------------------------------------- */

#define LINE_MAX_LEN 4096
static const char *LINE_END = "\r\n";

// log.h: typedef struct log_content_ctx log_content_ctx_t;
/* -------------------------------------------------------------------------- */
struct log_content_ctx {
	unsigned int open: 1;
	union {
		struct {char *header_req; char *header_resp;} file;
		struct {int fd; char *filename;} dir;
		struct {int fd; char *filename;} spec;
	} u;
};
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */


// NetGrok
/* -------------------------------------------------------------------------- */
// main function
/* -------------------------------------------------------------------------- */
int netgrok(log_content_ctx_t *ctx, logbuf_t *lb) {
	connection_t session;

	readAddresses(ctx -> u.file.header_resp, &session);
	interpretProtocol(&session);
	readHeaders(lb -> buf, lb -> sz, &session);
	printSession(&session);

	return 0; // success
}
/* -------------------------------------------------------------------------- */

// temporary solution for finding IP addresses and port numbers for connections
// by taking information from log file names; does not actually show direction
// of data flow for each session
/* -------------------------------------------------------------------------- */
void readAddresses(char *filepath, connection_t *session) {
	char filename[LINE_MAX_LEN];
	char *str, *next_str, *prev_str;

	strncpy(filename, filepath, LINE_MAX_LEN);
	filename[LINE_MAX_LEN - 1] = '\0'; // in case null terminator not found

	// filename: dir/dir/timestamp-src_ip,src_port-dst_ip,dst_port.log
	prev_str = NULL;
	str = strtok_r(filename, "/", &next_str);
	while (str != NULL) {
		prev_str = str;
		str = strtok_r(NULL, "/", &next_str);
	}

	// prev_str: timestamp-src_ip,src_port-dst_ip,dst_port.log
	if (prev_str != NULL) {
		str = strtok_r(prev_str, "-", &next_str); // str: timestamp

		str = strtok_r(NULL, ",", &next_str); // str: src_ip
		strncpy(session -> src_ip, str, IP_MAX_LEN);
		session -> src_ip[IP_MAX_LEN - 1] = '\0';

		str = strtok_r(NULL, "-", &next_str); // str: src_port
		strncpy(session -> src_port, str, INT_MAX_LEN);
		session -> src_port[INT_MAX_LEN - 1] = '\0';

		str = strtok_r(NULL, ",", &next_str); // str: dst_ip
		strncpy(session -> dst_ip, str, IP_MAX_LEN);
		session -> dst_ip[IP_MAX_LEN - 1] = '\0';

		str = strtok_r(NULL, ".", &next_str); // str: dst_port
		strncpy(session -> dst_port, str, INT_MAX_LEN);
		session -> dst_port[INT_MAX_LEN - 1] = '\0';
	}
}
/* -------------------------------------------------------------------------- */

// temporary solution for finding the application layer protocol being used
// based on the port numbers used in the connection
/* -------------------------------------------------------------------------- */
void interpretProtocol(connection_t *session) {
	unsigned int port;
	enum {HTTP = 80, HTTPS = 443};

	port = atoi(session -> dst_port);

	switch (port) {
		case HTTP: strncpy(session -> protocol, "http", PROTOCOL_MAX_LEN); break;
		case HTTPS: strncpy(session -> protocol, "https", PROTOCOL_MAX_LEN); break;
		default: strncpy(session -> protocol, "unknown", PROTOCOL_MAX_LEN); break;
	}
}
/* -------------------------------------------------------------------------- */

void readHeaders(unsigned char *buf, ssize_t bufsize, connection_t *session) {
	FILE *content;
	ssize_t bytes_read;
	char *line;
	char line_copy[LINE_MAX_LEN];
	char *str, *next_str;
	size_t str_len;

	content = tmpfile();
	bytes_read = fwrite(buf, sizeof(char), bufsize, content);
	snprintf(session -> bytes, INT_MAX_LEN, "%li", bytes_read);
	line = (char *) malloc(sizeof(char) * LINE_MAX_LEN);

	rewind(content);

	while (fgets(line, LINE_MAX_LEN, content) && isprint(line[0])) {
		strncpy(line_copy, line, LINE_MAX_LEN); // line includes null terminator
		str = strtok_r(line_copy, " ", &next_str);

		if (str != NULL) {
			str_len = strlen(str);

			for (int h = 0; h < HEADERS_TOTAL; h++) {
				if (areSameStrings(str, headers[h], str_len)) {
					switch (h) {
						case HOST_HEADER:
						 	str = strtok_r(NULL, LINE_END, &next_str);
							strncpy(session -> host, str, HOST_MAX_LEN);
							session -> host[HOST_MAX_LEN - 1] = '\0';
							break;
						case REFERER_HEADER:
							str = strtok_r(NULL, LINE_END, &next_str);
							strncpy(session -> referer, str, REFERER_MAX_LEN);
							session -> host[REFERER_MAX_LEN - 1] = '\0';
							break;
					}
					break;
				}
			}
		}
	}

	free(line);
	fclose(content);
}

int areSameStrings(const char *lhs, const char *rhs, int len) {
	for (int i = 0; i < len; i++) {
		if (tolower(lhs[i]) != tolower(rhs[i])) return 0; // false
	}
	return 1; // true
}

void printSession(connection_t *session) {
	char *json[CONNECTION_SIZE];
	char *session_dict[CONNECTION_SIZE] = {
		session -> src_ip,
		session -> src_port,
		session -> dst_ip,
		session -> dst_port,
		session -> bytes,
		session -> protocol,
		session -> host,
		session -> referer
	};

	json[SRC_IP] = "\"src_ip\": \"";
	json[SRC_PORT] = "\", \"src_port\": \"";
	json[DST_IP] = "\", \"dst_ip\": \"";
	json[DST_PORT] = "\", \"dst_port\": \"";
	json[BYTES] = "\", \"bytes\": \"";
	json[PROTOCOL] = "\", protocol\": \"";
	if (session -> host[0] != '\0') json[HOST] = "\", \"host\": \"";
	else json[HOST] = "";
	if (session -> referer[0] != '\0') json[REFERER] = "\", \"referer\": \"";
	else json[REFERER] = "";

	printf("{");
	for (int i = 0; i < CONNECTION_SIZE; i++) {
		printf("%s%s", json[i], session_dict[i]);
	}
	printf("\"}\n");
}
/* -------------------------------------------------------------------------- */
