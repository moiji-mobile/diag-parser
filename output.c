#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <osmocom/gsm/rsl.h>
#include <osmocom/core/gsmtap.h>
#include <osmocom/core/gsmtap_util.h>
#include <assert.h>
#include <sys/time.h>
#include "output.h"


/* Pcap packet header */
struct trace_pkthdr
{
	struct   timeval ts;	/* time stamp */
	uint32_t caplen;	/* length of portion present  */
	uint32_t len;		/* length this packet (off wire) */
};
typedef struct trace_pkthdr trace_pkthdr_t;

static FILE *pcap_handle = NULL; 	/* Pcap handle */
static char pcap_buff[65535+1]; 	/* Working buffer for crafting the pcap packets */
static size_t gsmtap_offset; 		/* Offset where the gsmtap payload begins */
static size_t udplen_offset;		/* Offset where the udp length is stored */
static size_t iphdrchksum_offset;	/* Offset where the ip header checksum is stored */
static size_t iptotlen_offset;		/* Ip header total length offset */

static struct gsmtap_inst *gti = NULL;




/* Create a new pcap file */
static FILE* trace_dump_open(const char *output_file)
{
	FILE *handle = NULL;
	uint8_t pcap_hdr[24] = {0xd4,0xc3,0xb2,0xa1,
				0x02,0x00,0x04,0x00,
				0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,
				0xff,0xff,0x00,0x00,
				0x01,0x00,0x00,0x00};
	int rc;

	/* Create a new file */
	handle = fopen(output_file,"w");
	if (!handle) {
		fprintf(stderr, "Cannot open pcap file %s, %s\n", output_file, strerror(errno));
		exit(1);
	}

	/* Write header to file */
	rc = fwrite(pcap_hdr,sizeof(pcap_hdr),1,handle);
	assert(rc == 1);
	fflush(handle);

	return handle;
}

/* Dump a packet into pcap file */
static void trace_dump(trace_pkthdr_t *header, char *packet)
{
	int rc;
	uint32_t len;
	uint32_t timestamp[2];

	assert(pcap_handle != NULL);
	assert(header->caplen == header->len);

	/* Write header */
	timestamp[0] = header->ts.tv_sec;
	timestamp[1] = 0;

	rc = fwrite(timestamp,sizeof(timestamp),1,pcap_handle);
	assert(rc == 1);

	len = header->caplen;

	rc = fwrite(&len,sizeof(len),1,pcap_handle);
	assert(rc == 1);
	rc = fwrite(&len,sizeof(len),1,pcap_handle);
	assert(rc == 1);

	/* Write payload */
	rc = fwrite(packet,header->caplen,1,pcap_handle);
	assert(rc == 1);

	fflush(pcap_handle);
}

/* IP header checksum calculator */
/* Source: http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html */
static uint16_t ip_checksum(void* vdata,size_t length) {
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
static void trace_push_payload(unsigned char *payload_data, int payload_len, struct timeval *timestamp)
{
	struct trace_pkthdr pcap_pkthdr;
	int ip_hdr_checksum;

	/* Create pcap header */
	assert(payload_len + gsmtap_offset <= 65535);
	if(timestamp) {
		memmove(&pcap_pkthdr.ts,timestamp,sizeof(*timestamp));
	} else {
		pcap_pkthdr.ts.tv_sec = 0;
		pcap_pkthdr.ts.tv_usec = 0;
	}
	pcap_pkthdr.len = payload_len + gsmtap_offset;
	pcap_pkthdr.caplen = payload_len + gsmtap_offset;

	/* Copy payload data into pcap buffer */
	memcpy(&pcap_buff[gsmtap_offset],payload_data,payload_len);

	/* Patch udp length field */
	pcap_buff[udplen_offset] = ((payload_len+8) >> 8) & 0xFF;
	pcap_buff[udplen_offset+1] = (payload_len+8) & 0xFF;

	/* Patch ip total length field */
	pcap_buff[iptotlen_offset] = ((gsmtap_offset+payload_len-14) >> 8) & 0xFF;
	pcap_buff[iptotlen_offset+1] = (gsmtap_offset+payload_len-14) & 0xFF;

	/* Patch ip-header checksum */
	ip_hdr_checksum = ip_checksum(pcap_buff,gsmtap_offset);
	pcap_buff[iphdrchksum_offset] = (ip_hdr_checksum >> 8) & 0xFF;
	pcap_buff[iphdrchksum_offset+1] = ip_hdr_checksum & 0xFF;

	/* Dump to pcap file */
	trace_dump(&pcap_pkthdr, pcap_buff);
}

void net_init(const char *gsmtap_target, const char *pcap_target)
{
	/* Avoid double initalization */
	if(pcap_handle == NULL && pcap_target)
	{
		/* Create pcap file */
		pcap_handle = trace_dump_open(pcap_target);

		/* Prepare buffer with hand-crafted dummy ethernet+ip+udp header */
		char dummy_eth_hdr[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					0x00,0x00,0x00,0x00,0x08,0x00,0x45,0x00,
					0x00,0x4b,0xb8,0x20,0x40,0x00,0x40,0x11,
					0x00,0x00,0x7f,0x00,0x00,0x01,0x7f,0x00,
					0x00,0x01,0x7a,0x69,0x12,0x79,0xff,0xff,
					0x00,0x00};

		memcpy(pcap_buff,dummy_eth_hdr,sizeof(dummy_eth_hdr));
		gsmtap_offset = sizeof(dummy_eth_hdr);
		udplen_offset = sizeof(dummy_eth_hdr) - 4;
		iphdrchksum_offset = sizeof(dummy_eth_hdr) - 18;
		iptotlen_offset = 16;
	} else if (gsmtap_target) {
		/* GSMTAP init */
		int rc;
		gti = gsmtap_source_init(gsmtap_target, GSMTAP_UDP_PORT, 0);
		if (!gti) {
			fprintf(stderr, "Cannot initialize GSMTAP\n");
			abort();
		}
		rc = gsmtap_source_add_sink(gti);
		assert(rc >= 0);
	}
}

void net_destroy()
{
	/* Close pcap file */
	if (pcap_handle) {
		fclose(pcap_handle);
		pcap_handle = NULL;
	}
	if (gti) {
		// Found no counterpart to gsmtap_source_init that
		// would free resources. Doing that by hand, otherwise
		// we run out of file descriptors...
		close(gti->wq.bfd.fd);
		talloc_free(gti);
	}
}


void net_send_msg(struct radio_message *m)
{
	struct msgb *msgb = 0;
	uint8_t gsmtap_channel;

	if (!pcap_handle && !gti)
		return;

	if (!(m->flags & MSG_DECODED))
		return;

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
		if (m->flags & MSG_SDCCH) {
			msgb = gsmtap_makemsg_ex(0x0e, m->bb.arfcn[0], 0,
					 0, 0, 0, 0, 0, m->bb.data, m->msg_len);
		} else if (m->flags & MSG_BCCH) {
			msgb = gsmtap_makemsg_ex(0x0d, m->bb.arfcn[0], 0,
					 m->chan_nr, 0, 0, 0, 0, m->bb.data, m->msg_len);
		} else {
			/* no other types defined */
			return;
		}
		break;
	}

	if (msgb) {
		int del = 1;

		if (pcap_handle)
			trace_push_payload(msgb->data,msgb->data_len,&m->timestamp);
		if (gti) {
			int ret = gsmtap_sendmsg(gti, msgb);
			del = ret != 0;
		}
		if (del)
			msgb_free(msgb);
	}
}

