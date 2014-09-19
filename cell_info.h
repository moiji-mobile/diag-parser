#ifndef CELL_INFO_H
#define CELL_INFO_H

#include <osmocom/core/linuxlist.h>

struct session_info;

enum si_index {
	SI1 = 0,
	SI2, SI2b, SI2t, SI2q,
	SI3,
	SI4,
	SI5, SI5b, SI5t,
	SI6,
	SI13,

	SI_MAX
};

struct cell_info {
	int id;
	int stored;
	struct timeval first_seen;
	struct timeval last_seen;
	/* DIAG or Android */
	int mcc;
	int mnc;
	int lac;
	int cid;
	int rat;
	int bcch_arfcn;
	int c1;
	int c2;
	int power_sum;
	int power_count;
	/* SI3 */
	int msc_ver;
	int combined;
	int agch_blocks;
	int pag_mframes;
	int t3212;
	int dtx;
	/* SI3 & SI4 */
	int cro;
	int temp_offset;
	int pen_time;
	int pwr_offset;
	int gprs;

	struct gsm_sysinfo_freq arfcn_list[1024];

	uint32_t si_counter[SI_MAX];
	uint8_t si_data[SI_MAX][20];
	uint16_t a_count[SI_MAX];

	struct llist_head entry;
};

void cell_init(unsigned start_id);
void cell_destroy(void (*callback)(char *));
int get_mcc(uint8_t *digits);
int get_mnc(uint8_t *digits);
void handle_sysinfo(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint32_t fn);

#endif
