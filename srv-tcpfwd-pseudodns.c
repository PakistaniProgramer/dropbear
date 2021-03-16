#include "includes.h"
//#include "tcpfwd.h"
//#include "session.h"
//#include "buffer.h"
//#include "packet.h"
#include "auth.h"
//#include "netio.h"
#include "srv-tcpfwd-pseudodns.h"

#if DROPBEAR_SVR_REMOTETCPFWD

static int make_socket(char* path, int create) {
	struct sockaddr_un addr = {0};
	int fd;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("Can't open socket");
		return EXIT_FAILURE;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);
	if (path[0] == '@') {
		addr.sun_path[0] = '\0';
	}
	if (create) {
		if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
			dropbear_log(LOG_ERR, "Can't bind pseudodns socket %s", path);
			return -1;
		}
		if (listen(fd, 5) == -1) {
			dropbear_log(LOG_ERR, "Can't listen pseudodns socket %s", path);
			return -1;
		}
	} else {
			if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
			dropbear_log(LOG_ERR, "Can't connect pseudodns socket %s", path);
			return -1;
		}
	}
	return fd;
}

static int send_and_read_packet(int fd, struct PseudoDNSNetworkPacket *buf) {
	const int size = sizeof(struct PseudoDNSNetworkPacket);
	if (send(fd, buf, size, 0) != size) {
		dropbear_log(LOG_ERR, "Can't send data to PseudoDNS");
		return 1;
	} else
	if (recv(fd, buf, size, 0) != size) {
		dropbear_log(LOG_ERR, "Can't read data from PseudoDNS");
		return 1;
	}
	return 0;
}

static int pseudodb_compar(struct PseudoDNSEntry *entry1, struct PseudoDNSEntry *entry2) {
	if (entry1->real_port && !entry2->real_port) {return -1;}
	if (!entry1->real_port && entry2->real_port) {return 1;}
	return 0;
}

static void pseudodb_optimize(struct PseudoDNSEntry *pseudodb, int *pseudodb_maxi) {
	int last_zero = *pseudodb_maxi;

	TRACE(("pseudodb_optimize enter"))

	dropbear_log(LOG_INFO, "BEFORE optimizing DB (pseudodb_maxi = %d):", *pseudodb_maxi);
	for (int i=0; i<MAX_PSEUDODNS_RECORDS; i++) {
		if (pseudodb[i].real_port) {
			dropbear_log(LOG_INFO, "[%d] %u", i, pseudodb[i].real_port);
		}
	}

	qsort(pseudodb, *pseudodb_maxi + 1,
		  sizeof(struct PseudoDNSEntry), pseudodb_compar);
	for (int i=*pseudodb_maxi; i>=0; i--) {
		if (!pseudodb[i].real_port) {
			last_zero = i;
		} else {
			break;
		}
	}
	*pseudodb_maxi = last_zero;

	dropbear_log(LOG_INFO, "After optimizing DB (pseudodb_maxi = %d):", *pseudodb_maxi);
	for (int i=0; i<MAX_PSEUDODNS_RECORDS; i++) {
		if (pseudodb[i].real_port) {
			dropbear_log(LOG_INFO, "[%d] %u", i, pseudodb[i].real_port);
		}
	}
}

void srv_pseudodns_main() {
	struct PseudoDNSEntry pseudodb[MAX_PSEUDODNS_RECORDS] = {0};
	int pseudodb_maxi = 0;
	int fd, client;
	struct PseudoDNSNetworkPacket buf;

	TRACE(("enter srv_pseudodns_main"))

	signal(SIGINT, SIG_DFL);

	fd = make_socket(PSEUDODNS_SOCK_NAME, 1);
	if (fd < 0) {
		dropbear_log(LOG_ERR, "PseudoDNS server could not be started");
		return;
	}

	for (;;) {
		if ((client = accept(fd, NULL, NULL)) == -1) {
			break;
		}
		if (recv(client, &buf, sizeof(buf), 0) == sizeof(buf)) {
			if (buf.packet_type == PSEUDO_ADD) { // PSEUDO_ADD
				buf.packet_type=PSEUDO_ERR;
				for (int i=0; i < MAX_PSEUDODNS_RECORDS; i++) {
					if (pseudodb[i].real_port == 0) {
						memcpy(&(pseudodb[i]), &buf.dns_entry, sizeof(pseudodb[i]));
						if (pseudodb_maxi < i) {pseudodb_maxi = i;}
						buf.packet_type=PSEUDO_DONE;
						dropbear_log(LOG_INFO, "Forwarding record added: [%s] %s:%u -> %u",
									 pseudodb[i].username, pseudodb[i].requested_host,
									 pseudodb[i].requested_port, pseudodb[i].real_port);
						break;
					}
				}
			} else
			if (buf.packet_type == PSEUDO_GET) { // PSEUDO_GET
				buf.packet_type=PSEUDO_ERR;
				for (int i=0; i <= pseudodb_maxi; i++) {
					if (strncmp(pseudodb[i].username, buf.dns_entry.username, MAX_USERNAME_LEN) == 0
						&& strncmp(pseudodb[i].requested_host, buf.dns_entry.requested_host, MAX_HOST_LEN) == 0
						&& pseudodb[i].requested_port == buf.dns_entry.requested_port
					) {
						memcpy(&buf.dns_entry, &(pseudodb[i]), sizeof(pseudodb[i]));
						buf.packet_type=PSEUDO_DONE;
						break;
					}
				}
			} else
			if (buf.packet_type == PSEUDO_RM) { // PSEUDO_RM
				buf.packet_type=PSEUDO_ERR;
				// optimize db randomly
				if (buf.dns_entry.real_port % 5 == 0) {
					pseudodb_optimize(&pseudodb, &pseudodb_maxi);
				}

				for (int i=0; i <= pseudodb_maxi; i++) {
					if (pseudodb[i].real_port == buf.dns_entry.real_port) {
						dropbear_log(LOG_INFO, "Forwarding record removed: [%s] %s:%u -> %u",
									pseudodb[i].username, pseudodb[i].requested_host,
									pseudodb[i].requested_port, pseudodb[i].real_port);
						memset(&(pseudodb[i]), '\0', sizeof(pseudodb[i]));
						buf.packet_type=PSEUDO_DONE;
						break;
					}
				}
			} else
			if (buf.packet_type == PSEUDO_ESLOT) { // PSEUDO_ESLOT
				buf.packet_type=PSEUDO_ERR;

				for (int i = 0; i < MAX_PSEUDODNS_RECORDS; i++) {
					if (pseudodb[i].real_port) {
						dropbear_log(LOG_INFO, "CURRENT[%d]: [%s] %s, %hu -> %hu", i, pseudodb[i].username, pseudodb[i].requested_host, pseudodb[i].requested_port, pseudodb[i].real_port);
					}
				}

#if MAX_PSEUDODNS_RECORDS_PER_USER
				/* Check user slot count */
				int user_slot_count = 0;
				for (int i=0; i <= pseudodb_maxi; i++) {
					if (strncmp(pseudodb[i].username, buf.dns_entry.username, MAX_USERNAME_LEN) == 0) {
						user_slot_count++;
					}
				}
				dropbear_log(LOG_INFO, "USERNAME %s HAS %d SOCKETS", buf.dns_entry.username, user_slot_count);
				if (user_slot_count < MAX_PSEUDODNS_RECORDS_PER_USER) {
#else
				if (1) {
#endif
					/* Check for empty slots */
					if (pseudodb_maxi + 1 < MAX_PSEUDODNS_RECORDS) {
						buf.packet_type=PSEUDO_DONE;
					} else {
						for (int i=0; i < MAX_PSEUDODNS_RECORDS; i++) {
							if (pseudodb[i].real_port == 0) {
								buf.packet_type=PSEUDO_DONE;
								break;
							}
						}
					}
				}
			}
			send(client, &buf, sizeof(buf), 0);
		}
		close(client);

		for (int i = 0; i < MAX_PSEUDODNS_RECORDS; i++) {
			if (pseudodb[i].real_port) {
				TRACE(("CURRENT[%d]: %s, %s, %hu -> %hu", i, pseudodb[i].username, pseudodb[i].requested_host, pseudodb[i].requested_port, pseudodb[i].real_port))
			}
		}
	}
	TRACE(("leave srv_pseudodns_main"))
}

int pseudodns_add_entry(const char* username, const char* requested_host, unsigned short requested_port, unsigned short real_port) {
	struct PseudoDNSNetworkPacket buf = {0};
	int fd;

	fd = make_socket(PSEUDODNS_SOCK_NAME, 0);
	if (fd < 0) {
		dropbear_log(LOG_ERR, "Can't open connection to PseudoDNS");
		return 1;
	}

	buf.packet_type = PSEUDO_ADD;
	strncpy(buf.dns_entry.username, username, MAX_USERNAME_LEN);
	strncpy(buf.dns_entry.requested_host, requested_host, MAX_HOST_LEN);
	buf.dns_entry.requested_port = requested_port;
	buf.dns_entry.real_port = real_port;

	if (send_and_read_packet(fd, &buf)) {
		close(fd);
		return 1;
	}

	TRACE(("!!! Packet type = %hu", buf.packet_type))
	close(fd);
	return !(buf.packet_type == PSEUDO_DONE);
}

int pseudodns_remove_entry(unsigned short real_port) {
	struct PseudoDNSNetworkPacket buf = {0};
	int fd;

	fd = make_socket(PSEUDODNS_SOCK_NAME, 0);
	if (fd < 0) {
		dropbear_log(LOG_ERR, "Can't open connection to PseudoDNS");
		return 1;
	}

	buf.packet_type = PSEUDO_RM;
	buf.dns_entry.real_port = real_port;

	if (send_and_read_packet(fd, &buf)) {
		close(fd);
		return 1;
	}

	TRACE(("### Packet type = %hu", buf.packet_type))
	close(fd);
	return !(buf.packet_type == PSEUDO_DONE);
}

int pseudodns_get_entry(const char* username, const char* requested_host, unsigned short requested_port) {
	struct PseudoDNSNetworkPacket buf = {0};
	int fd;

	fd = make_socket(PSEUDODNS_SOCK_NAME, 0);
	if (fd < 0) {
		dropbear_log(LOG_ERR, "Can't open connection to PseudoDNS");
		return 1;
	}

	buf.packet_type = PSEUDO_GET;
	strncpy(buf.dns_entry.username, username, MAX_USERNAME_LEN);
	strncpy(buf.dns_entry.requested_host, requested_host, MAX_HOST_LEN);
	buf.dns_entry.requested_port = requested_port;

	if (send_and_read_packet(fd, &buf)) {
		close(fd);
		return 0; // 0 is here for a reason, not a mistake
	}

	TRACE(("@@@ Packet type = %hu", buf.packet_type))
	close(fd);
	return buf.dns_entry.real_port;
}

int pseudodns_check_slot(const char* username) {
	struct PseudoDNSNetworkPacket buf = {0};
	int fd;

	fd = make_socket(PSEUDODNS_SOCK_NAME, 0);
	if (fd < 0) {
		dropbear_log(LOG_ERR, "Can't open connection to PseudoDNS");
		return 1;
	}

	buf.packet_type = PSEUDO_ESLOT;
	strncpy(buf.dns_entry.username, username, MAX_USERNAME_LEN);

	if (send_and_read_packet(fd, &buf)) {
		close(fd);
		return 1;
	}

	TRACE(("$$$ Packet type = %hu", buf.packet_type))
	close(fd);
	return !(buf.packet_type == PSEUDO_DONE);
}


#endif
