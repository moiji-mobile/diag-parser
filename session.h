#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <sys/time.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include "process.h"
#include "rand_check.h"
#include "assignment.h"
#include "cell_info.h"

struct frame_count {
	int unenc;
	int unenc_rand;
	int enc;
	int enc_rand;
	int enc_null;
	int enc_null_rand;
	int enc_si;
	int enc_si_rand;
	int predict;
	int power_count;
	int power_sum;
};

struct lapdm_buf {
	unsigned len;
	uint8_t data[20*32];
	uint8_t nr;
	uint8_t ns;
};

struct session_info {
	int id;
	char name[1024];
	struct timeval timestamp;
	int rat;
	int domain;
	int mcc;
	int mnc;
	int lac;
	int cid;
	int psc;
	int arfcn;
	int neigh_count;
	int started;
	int closed;
	int cracked;
	int processing;
	int decoded;
	int have_key;
	int no_key;
	uint8_t key[8];
	uint8_t initial_seq;
	uint8_t cipher_seq;
	int cipher_missing;
	uint32_t cm_cmd_fn;
	uint32_t cm_comp_first_fn;
	uint32_t cm_comp_last_fn;
	int cm_comp_count;
	uint32_t cipher_delta;
	int cipher;
	int integrity;
	uint32_t first_fn;
	uint32_t last_fn;
	uint32_t duration;
	uint32_t auth_delta;
	uint32_t auth_req_fn;
	uint32_t auth_resp_fn;
	int uplink;
	int avg_power;
	int mo;
	int mt;
	int unknown;
	int detach;
	int locupd;
	int lu_acc;
	int lu_rej_cause;
	int lu_type;
	int lu_mcc;
	int lu_mnc;
	int lu_lac;
	int pag_mi;
	int serv_req;
	int call;
	int sms;
	int ssa;
	int raupd;
	int attach;
	int att_acc;
	int pdp_activate;
	char pdp_ip[16];
	int tmsi_realloc;
	int release;
	int rr_cause;
	int have_gprs;
	int auth;
	int iden_imsi_bc;
	int iden_imei_bc;
	int iden_imsi_ac;
	int iden_imei_ac;
	int cmc_imeisv;
	int ms_cipher_mask;
	int ue_cipher_cap;
	int ue_integrity_cap;
	int assignment;
	int assign_complete;
	int handover;
	int forced_ho;
	int use_tmsi;
	int use_imsi;
	int use_jump;
	float r_time;
	int sms_presence;
	int call_presence;
	uint8_t old_tmsi[4];
	uint8_t new_tmsi[4];
	uint8_t tlli[4];
	char imsi[GSM48_MI_SIZE];
	char imei[GSM48_MI_SIZE];
	char msisdn[GSM48_MI_SIZE];
	struct gsm_assignment ga;
	struct frame_count fc;
	struct burst_buf bcch;
	struct burst_buf sdcch;
	struct burst_buf sacch;
	struct burst_buf facch[2];
	struct lapdm_buf chan_sdcch[2*2];
	struct lapdm_buf chan_sacch[2*2];
	struct lapdm_buf chan_facch[2*2];
	struct burst_buf saccht[4];
	struct burst_buf gprs[16];
	uint8_t last_dtap[256];
	uint8_t last_dtap_len;
	uint8_t last_dtap_rat;
	struct radio_message *first_msg;
	struct radio_message *last_msg;
	struct sms_meta *sms_list;
	struct session_info *next;
	struct session_info *prev;
	struct gsm_sysinfo_freq cell_arfcns[1024];
	struct gsm48_cell_options cell_options;
	struct cell_info ci;
	struct rand_state null;
	struct rand_state si5;
	struct rand_state si5bis;
	struct rand_state si5ter;
	struct rand_state si6;
	struct rand_state other_sdcch;
	struct rand_state other_sacch;
	void (*sql_callback)(const char *);
};

#define CALLBACK_NONE 0
#define CALLBACK_MYSQL 1
#define CALLBACK_SQLITE 2
#define CALLBACK_CONSOLE 3

#define SET_MSG_INFO(s, ... )  snprintf((s)->last_msg->info, sizeof((s)->last_msg->info), ##__VA_ARGS__);
#define APPEND_MSG_INFO(s, ...) snprintf((s)->last_msg->info+strlen((s)->last_msg->info), sizeof((s)->last_msg->info)-strlen((s)->last_msg->info), ##__VA_ARGS__);

void session_init();
void session_destroy();
struct session_info *session_create(int id, char* name, uint8_t *key, int mcc, int mnc, int lac, int cid, struct gsm_sysinfo_freq *ca);
void session_close(struct session_info *s);
void session_store(struct session_info *s);
void session_reset(struct session_info *s);
void session_free(struct session_info *s);
int session_enumerate();

extern unsigned privacy;
extern unsigned msg_verbose;
extern struct session_info _s[2];

#endif
