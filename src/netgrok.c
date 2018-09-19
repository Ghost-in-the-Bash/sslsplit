/* -----------------------------------------------------------------------------
The netgrok() function takes input passed in from pxy_bev_readcb() in pxyconn.c.
It then outputs info about the connections in JSON format to an inter-process
socket.

The pxy_bev_readcb() function in pxyconn.c is modified (starting at line 1786)
to setup the connection information for NetGrok and call netgrok(). It is the
only C file in SSLsplit that has been modified.
----------------------------------------------------------------------------- */
#include "netgrok.h"

// definitions and global variables
// -----------------------------------------------------------------------------
// struct that stores details about each connection
// ---------------------------------------------------------------------------
struct socket_address {char *ip_str; char *port_str;};
typedef struct socket_address sock_addr_t;

struct connection_context {
	sock_addr_t src;   sock_addr_t dst;
	size_t      size;  char        *protocol;
};
typedef struct connection_context conn_ctx_t;

struct connection {
	conn_ctx_t *ctx;
	char *time_str;
	struct {char *host; char *referer;} http;
};
// netgrok.h: typedef struct connection conn_t;
// ---------------------------------------------------------------------------

// string lines
// ---------------------------------------------------------------------------
static const char *LINE_END = "\r\n";
// ---------------------------------------------------------------------------

// inter-process socket for netgrok to publish its JSON dumps to
// ---------------------------------------------------------------------------
#define ENDPOINT "ipc://netgrok_socket"
static void *zmq_context;
static void *publisher_socket;

// for interrupt handler
// -------------------------------------------------------------------------
#define NO_FLAGS 0
static struct sigaction signal_action;
// -------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// -----------------------------------------------------------------------------


// main NetGrok function
// -----------------------------------------------------------------------------
int netgrok(void *connection_context, unsigned char *content) {
	conn_t *connection;
	char json_str[LINE_MAX_LEN];
	char host[HOST_MAX_LEN] ;
	char referer[REFERER_MAX_LEN];

	connection = (conn_t *) malloc(sizeof(struct connection));
	connection -> time_str = (char *) malloc(sizeof(char) * TIME_STR_LEN);
	connection -> http.host = host;
	connection -> http.referer = referer;

	assert(recordTime(connection -> time_str) == 0);
	connection -> ctx = (conn_ctx_t *) connection_context;
	assert(readHeaders(content, connection -> ctx -> size, connection) == 0);
	assert(getJsonStr(connection, json_str) == 0);
	assert(publish(json_str, strlen(json_str)) == 0);
	printf("%s\n", json_str);

	free(connection -> time_str);
	free(connection);

	return 0; // success
}
// -----------------------------------------------------------------------------


// get the current time and write it into the connection struct
// -----------------------------------------------------------------------------
int recordTime(char *time_str) {
	time_t timer;
	struct tm time_struct;

	timer = time(NULL);
	localtime_r(&timer, &time_struct);

	// TIME_FORMAT == "%Y-%m-%d %H:%M:%S" == "yyyy-mm-dd HH:mm:ss"
	strftime(time_str, TIME_STR_LEN, TIME_FORMAT, &time_struct);

	return 0;
}
// -----------------------------------------------------------------------------

/* reads from HTTP content, checking for headers and modifying the connection
struct to include the headers we're looking for (protocol, host, and referer) */
// -----------------------------------------------------------------------------
int readHeaders(unsigned char *buf, ssize_t bufsize, conn_t *connection) {
	FILE *content;
	ssize_t bytes_read;
	char *line;
	char line_copy[LINE_MAX_LEN];
	char *str, *next_str;
	size_t str_len;

	content = tmpfile();
	bytes_read = fwrite(buf, sizeof(char), bufsize, content);
	assert(bytes_read == bufsize);
	rewind(content);
	line = (char *) malloc(sizeof(char) * LINE_MAX_LEN);

	static char  *headers[]    = {"http*", "host:", "referer:"};
	static size_t header_len[] = {   5,       5,        8     };
	int           seen[]       = {   0,       0,        0     };
	int seen_protocol = 0;
	static int num_headers = sizeof(headers) / sizeof(char *);
	enum {HTTP_HEADER = 0, HOST_HEADER = 1, REFERER_HEADER = 2};

	// parse the first token of each line to see if it is a header we care about
	while (fgets(line, LINE_MAX_LEN, content) && isprint(line[0])) {
		strncpy(line_copy, line, LINE_MAX_LEN);
		line_copy[LINE_MAX_LEN - 1] = '\0'; // line includes null terminator
		str = strtok_r(line_copy, " ", &next_str);

		int header = 0;

		// compare the first string token to each type of header we are looking for
		while (str != NULL && header < num_headers) {
			str_len = strlen(str);

			if (!seen[header] && header_len[header] <= str_len) {
				str_len = header_len[header];

				if (areSameStrings(headers[header], str, str_len)) {
					str = strtok_r(NULL, LINE_END, &next_str);

					switch (header) {
						case HTTP_HEADER:
							if (strncmp(connection -> ctx -> protocol, "ssl\0", 4) == 0)
								strncpy(connection -> ctx -> protocol, "https\0", 6);
							else strncpy(connection -> ctx -> protocol, "http\0", 5);
							seen_protocol = 1;
							break;
						case HOST_HEADER:
							strncpy(connection -> http.host, str, HOST_MAX_LEN);
							break;
						case REFERER_HEADER:
							strncpy(connection -> http.referer, str, REFERER_MAX_LEN);
							break;
					}

					seen[header] = 1;
					break;
				}
			}

			// if a protocol header is not yet found, parse the rest of the line
			if (!seen_protocol && header == num_headers - 1) {
				str = strtok_r(NULL, " ", &next_str);
				header = 0;
			}
			else header++;
		}

		// if every header has been found, stop parsing
		if (seen[HTTP_HEADER] && seen[HOST_HEADER] && seen[REFERER_HEADER]) break;
	}

	// if (seen[HTTP_HEADER]) printf("conntent:\n%s\n", buf);

	if (!seen[HOST_HEADER]) connection -> http.host = NULL;
	if (!seen[REFERER_HEADER]) connection -> http.referer = NULL;

	free(line);
	fclose(content);
	return 0;
}
// -----------------------------------------------------------------------------

/* compares two strings; case insensitive; if both strings are same up to a '*'
character, the strings are considered to be the same */
// -----------------------------------------------------------------------------
int areSameStrings(const char *lhs, const char *rhs, int len) {
	for (int i = 0; i < len; i++) {
		if (tolower(lhs[i]) != tolower(rhs[i])) {
			if (lhs[i] == '*' || rhs[i] == '*') return 1; // true
			else return 0; // false
		}
	}
	return 1; // true
}
// -----------------------------------------------------------------------------

// write a string (in JSON format) of information about the connection
// -----------------------------------------------------------------------------
int getJsonStr(conn_t *connection, char *json_str) {
	char *names[] = {
		"src_ip", "src_port", "dst_ip", "dst_port",
		"size",   "protocol", "host",   "referer",  "time"
	};
	char size_str[INT_STR_MAX_LEN];
	snprintf(size_str, INT_STR_MAX_LEN, "%zu", connection -> ctx -> size);
	char *values[] = {
		connection -> ctx -> src.ip_str, connection -> ctx -> src.port_str,
		connection -> ctx -> dst.ip_str, connection -> ctx -> dst.port_str,
		size_str,                        connection -> ctx -> protocol,
		connection -> http.host,         connection -> http.referer,
		connection -> time_str
	};
	char buf[LINE_MAX_LEN] = "";

	strncat(buf, "{", 1);
	assert(addToJsonStr(names[0], values[0], buf) == 0);
	int num_pairs = sizeof(names) / sizeof(char *);
	for (int i = 1; i < num_pairs; i++) {
		if (values[i] != NULL) {
			strncat(buf, ", ", 2);
			assert(addToJsonStr(names[i], values[i], buf) == 0);
		}
	}
	strncat(buf, "}\0", 2);

	strncpy(json_str, buf, LINE_MAX_LEN);

	return 0;
}

int addToJsonStr(char *name, char *value, char *buf) {
	strncat(buf, "\"", 1);
	strncat(buf, name, strlen(name));
	strncat(buf, "\": \"", 4);
	strncat(buf, value, strlen(value));
	strncat(buf, "\"", 1);
	return 0;
}
// -----------------------------------------------------------------------------

// publish using ZMQ
// -----------------------------------------------------------------------------
int publish(char *buf, int len) {
	// setup for interrupt handling
	// -------------------------------------------------------------------------
	signal_action.sa_handler = interruptHandler;
	signal_action.sa_flags = NO_FLAGS;
	sigemptyset(&signal_action.sa_mask);
	sigaction(SIGINT, &signal_action, NULL);
	sigaction(SIGTERM, &signal_action, NULL);
	// -------------------------------------------------------------------------

	if (!zmq_context) {
		zmq_context = zmq_ctx_new();
		assert(zmq_context);
	}

	if (!publisher_socket) {
		publisher_socket = zmq_socket(zmq_context, ZMQ_PUB);
		assert(publisher_socket);
		assert(zmq_bind(publisher_socket, ENDPOINT) == 0);
	}

	assert(zmq_send(publisher_socket, buf, len + 1, NO_FLAGS) == len + 1);

	return 0;
}

// clean up the ZMQ stuff if the program is stopped
// ---------------------------------------------------------------------------
void interruptHandler(int sig) {
	printf("\nsignal: %d; closing publisher socket now\n", sig);
	if (publisher_socket) zmq_close(publisher_socket);
	if (zmq_context) zmq_ctx_destroy(zmq_context);
	exit(sig);
}
// ---------------------------------------------------------------------------
// -----------------------------------------------------------------------------
