/*

The netgrok function takes input from logbuf.c, which has been modified (in the
logbuf_write_free function) to send log content to netgrok.c instead of writing
to a log file. The netgrok function then outputs a JSON dump of connection
information to standard output.

Additionally, log.c has been modified (in the log_content_dir_opencb function)
to remove the log files after their creation.

*/

#include "netgrok.h"

static enum protocol_t protocol;
static connection session;

static char *headers[HEADERS_ENUMERATED] = {"ssl", "tcp", "host:", "referer:"};

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

		for (int h = SSL_HEADER; h < HEADERS_ENUMERATED; h++) {
			char *header = headers[h];
			size_t header_len = strlen(header);
			if (head_len == header_len && same_strings(head, header, header_len)) {
				switch (h) {
					case SSL_HEADER: protocol = SSL; read_addresses(&session); break;
					case TCP_HEADER: protocol = TCP; read_addresses(&session); break;
					case HOST_HEADER:
						strncpy(session.host, strtok(NULL, " "), HOST_MAX_LEN - 1);
						break;
					case REFERER_HEADER:
						strncpy(session.referer, strtok(NULL, " "), URL_MAX_LEN - 1);
						break;
				}
				break;
			}
		}

		head = strtok(NULL, " ");
		while (head && protocol != HTTP && protocol != HTTPS) {
			if (same_strings(head, "http", 4)) {
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

	print_session(&session);
	fclose(tmp);
	return count;
}

int same_strings(const char *lhs, const char *rhs, size_t count) {
	for (unsigned int i = 0; i < count; i++) {
		if (towlower(lhs[i]) != towlower(rhs[i])) return 0; // false
	}
	return 1; // true
}

void read_addresses(connection *session) {
	strncpy(session -> src_ip, strtok(NULL, " "), IP_MAX_LEN - 1);
	strncpy(session -> src_port, strtok(NULL, " "), PORT_MAX_LEN - 1);
	strncpy(session -> dst_ip, strtok(NULL, " "), IP_MAX_LEN - 1);
	strncpy(session -> dst_port, strtok(NULL, " "), PORT_MAX_LEN - 1);
}

void print_session(connection *session) {
	char *json[JSON_MAX_SIZE];
	char *session_dict[JSON_MAX_SIZE] = {
		session -> protocol,
		session -> src_ip,
		session -> src_port,
		session -> dst_ip,
		session -> dst_port,
		session -> host,
		session -> referer
	};

	json[PROTOCOL_INDEX] = "\"protocol\": \"";
	json[SRC_IP_INDEX] = "\", \"src_ip\": \"";
	json[SRC_PORT_INDEX] = "\", \"src_port\": \"";
	json[DST_IP_INDEX] = "\", \"dst_ip\": \"";
	json[DST_PORT_INDEX] = "\", \"dst_port\": \"";
	if (session -> host[0] != '\0') json[HOST_INDEX] = "\", \"host\": \"";
	else json[HOST_INDEX] = "";
	if (session -> referer[0] != '\0') {
		json[REFERER_INDEX] = "\", \"referer\": \"";
	}
	else json[REFERER_INDEX] = "";

	printf("{");
	for (int i = PROTOCOL_INDEX; i < JSON_MAX_SIZE; i++) {
		printf("%s%s", json[i], session_dict[i]);
	}
	printf("\"}\n");
}
