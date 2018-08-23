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
#define CONNECTION_FIELDS 8
enum {
	SRC_IP = 0, SRC_PORT = 1, DST_IP = 2, DST_PORT = 3,
	BYTES = 4, PROTOCOL = 5, HOST = 6, REFERER = 7
};
#define IP_MAX_LEN 39
#define PORT_MAX_LEN 6
#define PROTOCOL_MAX_LEN 12
#define HOST_MAX_LEN 64
#define REFERER_MAX_LEN 2048
// netgrok.h: typedef struct connection connection_t;
struct connection {
	char src_ip[IP_MAX_LEN]; char src_port[PORT_MAX_LEN];
	char dst_ip[IP_MAX_LEN]; char dst_port[PORT_MAX_LEN];
	ssize_t bytes;
	char protocol[PROTOCOL_MAX_LEN];
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

// main function
/* -------------------------------------------------------------------------- */
int netgrok(log_content_ctx_t *ctx, logbuf_t *lb) {
	connection_t session;
	FILE *content;

	// readFilename(ctx -> u.file.header_resp, &session);

	content = tmpfile();
	session.bytes = fwrite(lb -> buf, sizeof(char), lb -> sz, content);
	if (session.bytes != lb -> sz) return -1; // error
	rewind(content);
	readHeaders(content, &session);
	fclose(content);

	return 0; // success
}
/* -------------------------------------------------------------------------- */

// filename format: dir/dir/timestamp-src_ip,src_port-dst_ip,dst_port.log
/*
void readFilename(char *filepath, connection_t *session) {
	char filename[LINE_MAX_LEN];
	char *dir, *next_dir;

	strncpy(filename, filepath, strlen(filepath));
	filename[LINE_MAX_LEN - 1] = '\0'; // in case null terminator not found

	dir = strtok_r(filename, "/", &next_dir);
	while (dir != NULL) dir = strtok_r(NULL, "/", &next_dir);
}
*/

void readHeaders(FILE *content, connection_t *session) {
	char *line;
	size_t line_len;
	char line_copy[LINE_MAX_LEN];
	char *str, *next_str;
	size_t str_len;

	line = (char *) malloc(sizeof(char) * LINE_MAX_LEN);
	line_len = LINE_MAX_LEN;

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
							strncpy(session -> host, str, HOST_MAX_LEN - 1);
							session -> host[HOST_MAX_LEN - 1] = '\0';
							break;
						case REFERER_HEADER:
							str = strtok_r(NULL, LINE_END, &next_str);
							strncpy(session -> referer, str, REFERER_MAX_LEN - 1);
							session -> host[REFERER_MAX_LEN - 1] = '\0';
							break;
					}
					break;
				}
			}
		}
	}

	free(line);
}

/*
static enum protocol_t protocol;
static connection_t session;

static char *headers[HEADERS_TOTAL] = {"ssl", "tcp", "host:", "referer:"};

ssize_t netgrok(unsigned char *buf, ssize_t len) {
	FILE *tmp;
	ssize_t count;
	char line[LINE_MAX_LEN];

	tmp = tmpfile();
	count = fwrite(buf, sizeof(char), len, tmp);
	rewind(tmp);
	session.host[0] = '\0';
	session.referer[0] = '\0';

	while (fgets(line, LINE_MAX_LEN, tmp) != NULL) {
		size_t line_len;
		char *head;
		size_t head_len;

		line_len = strlen(line);
		if (line_len > 2) {
			if (iswspace(line[line_len - 1])) {
				line[line_len - 1] = '\0';
				if (iswspace(line[line_len - 2])) line[line_len - 2] = '\0';
			}
		}

		head = strtok(line, " ");
		if (head == NULL) break;
		head_len = strlen(head);

		for (int h = SSL_HEADER; h < HEADERS_TOTAL; h++) {
			char *header = headers[h];
			size_t header_len = strlen(header);
			if (head_len == header_len && areSameStrings(head, header, header_len)) {
				switch (h) {
					case SSL_HEADER: protocol = SSL; readAddresses(&session); break;
					case TCP_HEADER: protocol = TCP; readAddresses(&session); break;
					case HOST_HEADER:
						strncpy(session.host, strtok(NULL, " "), HOST_MAX_LEN - 1);
						break;
					case REFERER_HEADER:
						strncpy(session.referer, strtok(NULL, " "), REFERER_MAX_LEN - 1);
						break;
				}
				break;
			}
		}

		head = strtok(NULL, " ");
		while (head != NULL && protocol != HTTP && protocol != HTTPS) {
			if (areSameStrings(head, "http", 4)) {
				if (protocol == SSL) protocol = HTTPS;
				else protocol = HTTP;
				break;
			}
			head = strtok(NULL, " ");
		}
	}

	switch (protocol) {
		case SSL: strncpy(session.protocol, "ssl", 4); break;
		case TCP: strncpy(session.protocol, "tcp", 4); break;
		case HTTP: strncpy(session.protocol, "http", 5); break;
		case HTTPS: strncpy(session.protocol, "https", 6); break;
		default: strncpy(session.protocol, "tcp", 4); break;
	}

	printSession(&session);
	fclose(tmp);
	return count;
}
*/

int areSameStrings(const char *lhs, const char *rhs, int len) {
	for (int i = 0; i < len; i++) {
		if (tolower(lhs[i]) != tolower(rhs[i])) return 0; // false
	}
	return 1; // true
}

void readAddresses(connection_t *session) {
	strncpy(session -> src_ip, strtok(NULL, " "), IP_MAX_LEN - 1);
	strncpy(session -> src_port, strtok(NULL, " "), PORT_MAX_LEN - 1);
	strncpy(session -> dst_ip, strtok(NULL, " "), IP_MAX_LEN - 1);
	strncpy(session -> dst_port, strtok(NULL, " "), PORT_MAX_LEN - 1);
}

void printSession(connection_t *session) {
	char *json[CONNECTION_FIELDS];
	char *session_dict[CONNECTION_FIELDS] = {
		session -> protocol,
		session -> src_ip,
		session -> src_port,
		session -> dst_ip,
		session -> dst_port,
		session -> host,
		session -> referer
	};

	json[PROTOCOL] = "\"protocol\": \"";
	json[SRC_IP] = "\", \"src_ip\": \"";
	json[SRC_PORT] = "\", \"src_port\": \"";
	json[DST_IP] = "\", \"dst_ip\": \"";
	json[DST_PORT] = "\", \"dst_port\": \"";
	if (session -> host[0] != '\0') json[HOST] = "\", \"host\": \"";
	else json[HOST] = "";
	if (session -> referer[0] != '\0') {
		json[REFERER] = "\", \"referer\": \"";
	}
	else json[REFERER] = "";

	printf("{");
	for (int i = 0; i < CONNECTION_FIELDS; i++) {
		printf("%s%s", json[i], session_dict[i]);
	}
	printf("\"}\n");
}
