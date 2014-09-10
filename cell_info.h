#ifndef CELL_INFO_H
#define CELL_INFO_H

#include <osmocom/core/linuxlist.h>

struct cell_info {
	int id;
	struct timeval first_seen;
	struct timeval last_seen;
	int mcc;
	int mnc;
	int lac;
	int cid;
	int rat;
	int bcch_arfcn;
	int ba_len;
	int power_sum;
	int power_count;
	int combined;
	int gprs;
	int t3212;
	int cro;
	int c1;
	int c2;
	int agch_blocks;
	int neigh_2_count;
	int neigh_2b_count;
	int neigh_2t_count;
	int neigh_2q_count;
	int neigh_5_count;
	int neigh_5b_count;
	int neigh_5t_count;
	struct gsm_sysinfo_freq bcch_list[1024];
	struct gsm_sysinfo_freq neigh_list[1024];
	uint8_t si1[23];
	uint8_t si2[23];
	uint8_t si2b[23];
	uint8_t si2t[23];
	uint8_t si2q[23];
	uint8_t si3[23];
	uint8_t si4[23];
	uint8_t si5[23];
	uint8_t si5b[23];
	uint8_t si5t[23];
	uint8_t si6[23];
	uint8_t si13[23];

	struct llist_head entry;
};

int get_mcc(uint8_t *digits);
int get_mnc(uint8_t *digits);
void handle_lai(struct session_info *s, uint8_t *data, int cid);
void handle_sysinfo(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint32_t fn);

#endif
