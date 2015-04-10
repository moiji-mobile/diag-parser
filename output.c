#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/gsmtap_util.h>
#ifdef USE_PCAP
#include <pcap.h>
#include <assert.h>
#include <sys/time.h>
#endif
#include "output.h"

#ifdef USE_PCAP
static pcap_dumper_t *pcap_dumper; 	/* Pcap handle */
char pcap_buff[65535+1]; 		/* Working buffer for crafting the pcap packets */
size_t gsmtap_offset; 			/* Offset where the gsmtap payload begins */
size_t udplen_offset;			/* Offset where the udp length is stored */
size_t iphdrchksum_offset;		/* Offset where the ip header checksum is stored */
#else
static struct gsmtap_inst *gti = NULL;
#endif

#ifdef USE_PCAP

/* IP header checksum calculator */
/* Source: http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html */
uint16_t ip_checksum(void* vdata,size_t length) {
	char* data=(char*)vdata;
	uint32_t acc=0xffff;
	size_t i;
	for (i=0;i+1<length;i+=2)
	{
		uint16_t word;
		memcpy(&word,data+i,2);
		acc+=ntohs(word);

		if (acc>0xffff) 
			acc-=0xffff;
	}

	if (length&1)
	{
		uint16_t word=0;
		memcpy(&word,data+length-1,1);
		acc+=ntohs(word);
		if (acc>0xffff)
			acc-=0xffff;
	}

	return htons(~acc);
}

/* Helper function to write some payload data into the pcap file */
static int trace_push_payload(unsigned char *payload_data, int payload_len, struct timeval *timestamp)
{
	struct pcap_pkthdr pcap_pkthdr;
	int ip_hdr_checksum;
	struct timeval dummy;

	/* Create pcap header */
	assert(payload_len + gsmtap_offset <= 65535);
	if(timestamp)
		pcap_pkthdr.ts = *timestamp;
	else
	{
		memset(&dummy,0,sizeof(struct timeval));
		pcap_pkthdr.ts = dummy;
	}
	pcap_pkthdr.len = payload_len + gsmtap_offset;
	pcap_pkthdr.caplen = payload_len + gsmtap_offset;

	/* Copy payload data into pcap buffer */
	memcpy(pcap_buff+gsmtap_offset,payload_data,payload_len);

	/* Patch udp length field */
	pcap_buff[udplen_offset] = ((payload_len+8) >> 8) & 0xFF;
	pcap_buff[udplen_offset+1] = (payload_len+8) & 0xFF;

	/* Patch ip-header checksum */
	ip_hdr_checksum = ip_checksum(pcap_buff,gsmtap_offset);
	pcap_buff[iphdrchksum_offset] = (ip_hdr_checksum >> 8) & 0xFF;
	pcap_buff[iphdrchksum_offset+1] = ip_hdr_checksum & 0xFF;

	pcap_dump((u_char*)pcap_dumper, &pcap_pkthdr, (u_char*)pcap_buff);

	return 0;
}
#endif

void net_init(const char *target)
{
#ifdef USE_PCAP
	/* Create pcap file */
	pcap_t *pcap_handle = NULL;
	pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
	pcap_dumper = pcap_dump_open(pcap_handle, target);

	/* Prepare buffer with hand-crafted dummy ethernet header */
	char dummy_eth_hdr[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x4b,0xb8,0x20,0x40,0x00,0x40,0x11,0x00,0x00,0x7f,0x00,0x00,0x01,0x7f,0x00,0x00,0x01,0x7a,0x69,0x12,0x79,0xff,0xff,0x00,0x00};
	memcpy(pcap_buff,dummy_eth_hdr,sizeof(dummy_eth_hdr));
	gsmtap_offset = sizeof(dummy_eth_hdr);
	udplen_offset = sizeof(dummy_eth_hdr) - 4;
	iphdrchksum_offset = sizeof(dummy_eth_hdr) - 18;
#else
	gti = gsmtap_source_init(target, GSMTAP_UDP_PORT, 0);
	if (!gti) {
		fprintf(stderr, "Cannot initialize GSMTAP\n");
		abort();
	}
	gsmtap_source_add_sink(gti);
#endif

}

void net_destroy()
{
#ifdef USE_PCAP
	/* Close pcap file */
	if (pcap_dumper) {
		pcap_dump_close(pcap_dumper);
	}
#else
	if (gti) {
		/* Flush GSMTAP message queue */
		while (osmo_select_main(1));

		// Found no counterpart to gsmtap_source_init that
		// would free resources. Doing that by hand, otherwise
		// we run out of file descriptors...
		close(gti->wq.bfd.fd);
		talloc_free(gti);
	}
#endif
}


void net_send_rlcmac(uint8_t *msg, int len, int ts, uint8_t ul)
{
#ifdef USE_PCAP
	struct msgb *msgb;
	msgb = gsmtap_makemsg(ul?ARFCN_UPLINK:0, ts, GSMTAP_CHANNEL_PACCH, 0, 0, 0, 0, msg, len);
	trace_push_payload(msgb->data,msgb->data_len,0);
#else
	if (gti) {
		//gsmtap_send(gti, ul?ARFCN_UPLINK:0, 0, 0xd, 0, 0, 0, 0, msg, len);
		gsmtap_send(gti, ul?ARFCN_UPLINK:0, ts, GSMTAP_CHANNEL_PACCH, 0, 0, 0, 0, msg, len);

	}
#endif
}


void net_send_llc(uint8_t *data, int len, uint8_t ul)
{
	struct msgb *msg;
	struct gsmtap_hdr *gh;
	uint8_t *dst;

#ifdef USE_PCAP
	if (!pcap_dumper)
		return;
#else
	if (!gti)
		return;
#endif

	if ((data[0] == 0x43) &&
	    (data[1] == 0xc0) &&
	    (data[2] == 0x01))
		return;

	msg = msgb_alloc(sizeof(*gh) + len, "gsmtap_tx");
	if (!msg)
	        return;

	gh = (struct gsmtap_hdr *) msgb_put(msg, sizeof(*gh));

	gh->version = GSMTAP_VERSION;
	gh->hdr_len = sizeof(*gh)/4;
	gh->type = 8;
	gh->timeslot = 0;
	gh->sub_slot = 0;
	gh->arfcn = ul ? htons(ARFCN_UPLINK) : 0;
	gh->snr_db = 0;
	gh->signal_dbm = 0;
	gh->frame_number = 0;
	gh->sub_type = 0;
	gh->antenna_nr = 0;

        dst = msgb_put(msg, len);
        memcpy(dst, data, len);

#ifdef USE_PCAP
	trace_push_payload(msg->data,msg->data_len,0);
#else
	gsmtap_sendmsg(gti, msg);
#endif

}

void net_send_msg(struct radio_message *m)
{
	struct msgb *msgb = 0;
	uint8_t gsmtap_channel;

#ifdef USE_PCAP
	if (!(pcap_dumper && (m->flags & MSG_DECODED)))
		return;
#else
	if (!(gti && (m->flags & MSG_DECODED)))
		return;
#endif

	switch (m->rat) {
	case RAT_GSM: {
		uint8_t ts, type, subch;

		rsl_dec_chan_nr(m->chan_nr, &type, &subch, &ts);

		gsmtap_channel = chantype_rsl2gsmtap(type, (m->flags & MSG_SACCH) ? 0x40 : 0);

		msgb = gsmtap_makemsg(m->bb.arfcn[0], ts, gsmtap_channel, subch,
				 m->bb.fn[0], m->bb.rxl[0], m->bb.snr[0], m->msg, m->msg_len);
		break;
	}

	case RAT_UMTS:
		if (m->flags & MSG_SDCCH) {
			if (m->bb.arfcn[0] & ARFCN_UPLINK) {
				gsmtap_channel = GSMTAP_RRC_SUB_UL_DCCH_Message;
			} else {
				gsmtap_channel = GSMTAP_RRC_SUB_DL_DCCH_Message;
			}
		} else if (m->flags & MSG_FACCH) {
			if (m->bb.arfcn[0] & ARFCN_UPLINK) {
				gsmtap_channel = GSMTAP_RRC_SUB_UL_CCCH_Message;
			} else {
				gsmtap_channel = GSMTAP_RRC_SUB_DL_CCCH_Message;
			}
		} else if (m->flags & MSG_BCCH) {
			gsmtap_channel = GSMTAP_RRC_SUB_BCCH_BCH_Message;
		} else {
			/* no other types defined */
			return;
		}
		msgb = gsmtap_makemsg_ex(GSMTAP_TYPE_UMTS_RRC, m->bb.arfcn[0], 0,
				 gsmtap_channel, 0, 0, 0, 0, m->bb.data, m->msg_len);
		break;
	case RAT_LTE:
		msgb = gsmtap_makemsg_ex(0x0e, m->bb.arfcn[0], 0,
					 0, 0, 0, 0, 0, m->bb.data, m->msg_len);
		break;
	}

	if (msgb) {
#ifdef USE_PCAP
		int ret = trace_push_payload(msgb->data,msgb->data_len,&m->timestamp);
#else
		int ret = gsmtap_sendmsg(gti, msgb);
#endif
		if (ret != 0) {
			msgb_free(msgb);
		} else {
			osmo_select_main(1);
		}
	}
}

