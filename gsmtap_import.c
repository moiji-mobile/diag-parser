#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/utils.h>

#include "session.h"
#include "process.h"
#include "cell_info.h"
#include "l3_handler.h"

void chantype_from_gsmtap(struct radio_message *m, uint8_t gsmtap_chantype, uint8_t timeslot)
{
	uint8_t rsl_type = 0;

	switch (gsmtap_chantype & ~GSMTAP_CHANNEL_ACCH) {
	case GSMTAP_CHANNEL_TCH_F:
		rsl_type = RSL_CHAN_Bm_ACCHs;
		m->flags = MSG_FACCH;
		break;
	case GSMTAP_CHANNEL_TCH_H:
		rsl_type = RSL_CHAN_Lm_ACCHs;
		m->flags = MSG_FACCH;
		break;
	case GSMTAP_CHANNEL_SDCCH4:
		rsl_type = RSL_CHAN_SDCCH4_ACCH;
		if (gsmtap_chantype & GSMTAP_CHANNEL_ACCH) {
			m->flags = MSG_SACCH;
		} else {
			m->flags = MSG_SDCCH;
		}
		break;
	case GSMTAP_CHANNEL_SDCCH8:
		rsl_type = RSL_CHAN_SDCCH8_ACCH;
		if (gsmtap_chantype & GSMTAP_CHANNEL_ACCH) {
			m->flags = MSG_SACCH;
		} else {
			m->flags = MSG_SDCCH;
		}
		break;
	case GSMTAP_CHANNEL_BCCH:
		rsl_type = RSL_CHAN_BCCH;
		m->flags = MSG_BCCH;
		break;
	case GSMTAP_CHANNEL_RACH:
		rsl_type = RSL_CHAN_RACH;
		m->flags = MSG_BCCH;
		break;
	case GSMTAP_CHANNEL_PCH:
		rsl_type = RSL_CHAN_PCH_AGCH;
		m->flags = MSG_BCCH;
		break;
	default:
		m->flags = 0;
		return;
	}

	m->chan_nr = (rsl_type << 3) | timeslot;
}

void process_gsmtap(const struct pcap_pkthdr* pkt_hdr, const u_char* pkt_data, uint32_t offset)
{
	struct gsmtap_hdr *gh;
	struct radio_message *m;

	assert(pkt_hdr->len - offset > 4);

	gh = (struct gsmtap_hdr *) (pkt_data + offset);

	assert(gh->version == 2);
	assert(pkt_hdr->len - offset > gh->hdr_len*4);

	offset += gh->hdr_len*4;

	m = (struct radio_message *) malloc(sizeof(struct radio_message));
	if (!m) {
		printf("Cannot allocate memory for radio message\n");
		exit(1);
	}

	memset(m, 0, sizeof(*m));

	m->bb.fn[0] = ntohl(gh->frame_number);
	m->bb.arfcn[0] = ntohs(gh->arfcn);
	m->msg_len = pkt_hdr->len - offset;

	switch (gh->type) {
	case GSMTAP_TYPE_UM:
		m->rat = RAT_GSM;
		chantype_from_gsmtap(m, gh->sub_type, gh->timeslot);
		memcpy(m->msg, &pkt_data[offset], m->msg_len);
		break;
	case GSMTAP_TYPE_UMTS_RRC:
		m->rat = RAT_UMTS;
		memcpy(m->bb.data, &pkt_data[offset], m->msg_len);
		break;
	case GSMTAP_TYPE_LTE_RRC:
		m->rat = RAT_LTE;
		memcpy(m->bb.data, &pkt_data[offset], m->msg_len);
		break;
	default:
		free(m);
		return;
	}

	if (m->flags) {
		_s->timestamp = pkt_hdr->ts;
		m->timestamp = pkt_hdr->ts;
		handle_radio_msg(_s, m);
	}
}

void process_udp(const struct pcap_pkthdr* pkt_hdr, const u_char* pkt_data, uint32_t offset)
{
	uint16_t *dport;

	assert(pkt_hdr->len - offset > 8);

	dport = (uint16_t *) &pkt_data[offset+2];

	/* check UDP port */
	if (ntohs(*dport) == GSMTAP_UDP_PORT) {
		process_gsmtap(pkt_hdr, (u_char *) pkt_data, offset+8);
	}
}

void process_ip(const struct pcap_pkthdr* pkt_hdr, const u_char* pkt_data, uint32_t offset)
{
	assert(pkt_hdr->len - offset > 20);

	/* check protocol */
	if (pkt_data[offset+9] == 0x11) {
		process_udp(pkt_hdr, pkt_data, offset+20);
	}
}

void process_vlan(const struct pcap_pkthdr* pkt_hdr, const u_char* pkt_data, uint32_t offset)
{
	uint16_t *etype;

	/* check inner ethertype */
	etype = (uint16_t *) &pkt_data[offset+2];
	if (ntohs(*etype) == 0x0800) {
		process_ip(pkt_hdr, pkt_data, offset+4);
	}
}

void process_ethernet(u_char *arg, const struct pcap_pkthdr* pkt_hdr, const u_char* pkt_data)
{
	uint16_t *etype;

	/* check ethertype */
	etype = (uint16_t *) &pkt_data[12];
	switch (ntohs(*etype)) {
	case 0x0800: // IP
		process_ip(pkt_hdr, pkt_data, 14);
		break;
	case 0x8100: // VLAN
		process_vlan(pkt_hdr, pkt_data, 14);
		break;
	}
}

int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *read_fp;

	if (argc < 4) {
		printf("Not enough arguments\n");
		printf("Usage: %s <file.pcap> <start session id> <start cell id>\n", argv[0]);
		return -1;
	}

	read_fp = pcap_open_offline(argv[1], errbuf);

	if (pcap_datalink(read_fp) != DLT_EN10MB) {
		printf("Wrong datalink type\n");
		return 1;
	}

	session_init(atoi(argv[2]), 1, 1, CALLBACK_MYSQL);
	//TODO: read timestamp from pcap header and replace the 0 below
	cell_init(atoi(argv[3]), 0, CALLBACK_MYSQL);
	//msg_verbose = 1;

	pcap_loop(read_fp, -1, process_ethernet, NULL);

	session_destroy();

	return 0;
}
