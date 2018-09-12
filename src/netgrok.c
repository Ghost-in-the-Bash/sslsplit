/* -----------------------------------------------------------------------------
The netgrok() function takes input passed in from log_content_submit() in log.c,
which has also been modified to not produce content logs. The netgrok() function
then outputs a JSON dump of connection information to a socket.
----------------------------------------------------------------------------- */

#include "netgrok.h"

// definitions
/* -------------------------------------------------------------------------- */
// struct that stores details about each connection
/* -------------------------------------------------------------------------- */
#define CONNECTION_SIZE 8
enum {
	SRC_IP = 0, SRC_PORT = 1, DST_IP = 2, DST_PORT = 3,
	BYTES  = 4, PROTOCOL = 5, HOST   = 6, REFERER  = 7
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

// text lines
/* -------------------------------------------------------------------------- */
#define LINE_MAX_LEN 4096
static const char *LINE_END = "\r\n";
/* -------------------------------------------------------------------------- */

// socket for netgrok to publish its JSON dumps to
/* -------------------------------------------------------------------------- */
#define ENDPOINT "ipc://netgrok_socket"
static void *context;
static void *publisher_socket;

// for interrupt handler
/* -------------------------------------------------------------------------- */
#define NO_FLAGS 0
static struct sigaction signal_action;
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

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
	char json[LINE_MAX_LEN];

	readAddresses(ctx -> u.file.header_resp, &session);
	interpretProtocol(&session);
	readHeaders(lb -> buf, lb -> sz, &session);
	sessToJSON(&session, json);
	publish(json, strlen(json));

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

// reads from HTTP headers; for now, assumes content contains HTTP
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
/* -------------------------------------------------------------------------- */

// compares two strings; case insensitive
/* -------------------------------------------------------------------------- */
int areSameStrings(const char *lhs, const char *rhs, int len) {
	for (int i = 0; i < len; i++) {
		if (tolower(lhs[i]) != tolower(rhs[i])) return 0; // false
	}
	return 1; // true
}
/* -------------------------------------------------------------------------- */

// write a string (in JSON format) of information about the connection
/* -------------------------------------------------------------------------- */
void sessToJSON(connection_t *session, char *buf) {
	char *names[CONNECTION_SIZE];
	char *values[CONNECTION_SIZE] = {
		session -> src_ip,
		session -> src_port,
		session -> dst_ip,
		session -> dst_port,
		session -> bytes,
		session -> protocol,
		session -> host,
		session -> referer
	};
	char json_dump[LINE_MAX_LEN] = "";

	// This is an ugly, tedious way to make a JSON dump, but whatever. I'll make a
	// cleaner, simpler way later. Maybe.
	/* ------------------------------------------------------------------------ */
	names[SRC_IP]   = "src_ip";
	names[SRC_PORT] = "src_port";
	names[DST_IP]   = "dst_ip";
	names[DST_PORT] = "dst_port";
	names[BYTES]    = "bytes";
	names[PROTOCOL] = "protocol";
	names[HOST]     = NULL;
	names[REFERER]  = NULL;

	if (session -> host[0]    != '\0') names[HOST]    = "host";
	if (session -> referer[0] != '\0') names[REFERER] = "referer";

	strncat(json_dump, "{\"", 2);
	strncat(json_dump, names[0], REFERER_MAX_LEN);
	strncat(json_dump, "\": \"", 4);
	strncat(json_dump, values[0], REFERER_MAX_LEN);
	strncat(json_dump, "\"", 1);
	for (int i = 1; i < CONNECTION_SIZE; i++) {
		if (names[i] != NULL) {
			strncat(json_dump, ", \"", 3);
			strncat(json_dump, names[i], REFERER_MAX_LEN);
			strncat(json_dump, "\": \"", 4);
			strncat(json_dump, values[i], REFERER_MAX_LEN);
			strncat(json_dump, "\"", 1);
		}
	}
	strncat(json_dump, "}\0", 2);
	/* ------------------------------------------------------------------------ */
	printf("%s\n", json_dump); // for debugging

	strncpy(buf, json_dump, LINE_MAX_LEN);
}
/* -------------------------------------------------------------------------- */

// publish using ZMQ
/* -------------------------------------------------------------------------- */
int publish(char *buf, int len) {
	// setup for interrupt handling
	/* ------------------------------------------------------------------------ */
	signal_action.sa_handler = interruptHandler;
	signal_action.sa_flags = NO_FLAGS;
	sigemptyset(&signal_action.sa_mask);
	sigaction(SIGINT, &signal_action, NULL);
	sigaction(SIGTERM, &signal_action, NULL);
	/* ------------------------------------------------------------------------ */

	if (!context) {
		context = zmq_ctx_new();
		assert(context);
	}

	if (!publisher_socket) {
		publisher_socket = zmq_socket(context, ZMQ_PUB);
		assert(publisher_socket);
		assert(zmq_bind(publisher_socket, ENDPOINT) == 0);
	}

	assert(zmq_send(publisher_socket, buf, len + 1, NO_FLAGS) == len + 1);

	return 0;
}
/* -------------------------------------------------------------------------- */

// clean up the ZMQ stuff if the program is stopped
/* -------------------------------------------------------------------------- */
void interruptHandler(int sig) {
	printf("\nsignal: %d; closing publisher socket now\n", sig);
	if (publisher_socket) zmq_close(publisher_socket);
	if (context) zmq_ctx_destroy(context);
	exit(sig);
}
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
