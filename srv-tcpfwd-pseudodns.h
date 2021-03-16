struct PseudoDNSEntry {
	char username[MAX_USERNAME_LEN + 1];
	char requested_host[MAX_HOST_LEN + 1];
	unsigned short requested_port;
	unsigned short real_port;
};
struct PseudoDNSNetworkPacket {
	enum packet_type {PSEUDO_ADD, PSEUDO_GET, PSEUDO_RM, PSEUDO_ESLOT, PSEUDO_DONE, PSEUDO_ERR} packet_type;
	struct PseudoDNSEntry dns_entry;
};

void srv_pseudodns_main();
int pseudodns_add_entry(const char* username, const char* requested_host, unsigned short requested_port, unsigned short real_port);
int pseudodns_remove_entry(unsigned short real_port);
int pseudodns_get_entry(const char* username, const char* requested_host, unsigned short requested_port);
int pseudodns_check_slot(const char* username);
