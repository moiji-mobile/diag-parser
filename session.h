#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>
#include <assert.h>
#include <sys/time.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include "process.h"
#include "rand_check.h"
#include "assignment.h"
#include "cell_info.h"

struct frame_count {
	uint32_t unenc;
	uint32_t unenc_rand;
	uint32_t enc;
	uint32_t enc_rand;
	uint32_t enc_null;
	uint32_t enc_null_rand;
	uint32_t enc_si;
	uint32_t enc_si_rand;
	uint32_t predict;
	uint32_t power_count;
	uint32_t power_sum;
} __attribute__((packed));

//Holds the state of one lapdm (lapd = a layer 2 protocol)
struct lapdm_buf {
	uint32_t len;
	uint8_t data[20*32];
	uint8_t nr; //sequence number of receiver
	uint8_t ns; //sequence number of sender
	uint16_t no_out_of_seq_sender_msgs;
	int16_t last_out_of_seq_msg_number;
};

struct session_info {
	int id;
	uint32_t appid;
	char name[1024];
	struct timeval timestamp;
	uint8_t rat;
	uint8_t domain;
	uint16_t mcc;
	uint16_t mnc;
	uint16_t lac;
	uint32_t cid;
	uint16_t psc;
	uint16_t arfcn;
	uint16_t neigh_count;
	uint8_t started;
	uint8_t closed;
	uint8_t cracked;
	uint8_t processing;
	int8_t decoded;
	uint8_t have_key;
	uint8_t no_key;
	uint8_t key[8];
	uint8_t initial_seq;
	uint8_t cipher_seq;
	int8_t cipher_missing;
	uint32_t cm_cmd_fn;
	uint32_t cm_comp_first_fn;
	uint32_t cm_comp_last_fn;
	uint16_t cm_comp_count;
	uint32_t cipher_delta;
	uint8_t cipher;
	uint8_t integrity;
	uint8_t cipher_nas;
	uint8_t integrity_nas;
	uint32_t first_fn;
	uint32_t last_fn;
	uint32_t duration;
	uint32_t auth_delta;
	uint32_t auth_req_fn;
	uint32_t auth_resp_fn;
	uint8_t uplink;
	uint32_t avg_power;
	uint8_t mo;
	uint8_t mt;
	uint8_t unknown;
	uint8_t detach;
	uint8_t locupd;
	uint8_t lu_type;
	uint8_t lu_acc;
	uint8_t lu_reject;
	uint8_t lu_rej_cause;
	uint16_t lu_mcc;
	uint16_t lu_mnc;
	uint16_t lu_lac;
	uint8_t pag_mi;
	uint8_t serv_req;
	uint8_t call;
	uint8_t sms;
	uint8_t ssa;
	uint8_t abort;
	uint8_t raupd;
	uint8_t attach;
	uint8_t att_acc;
	uint8_t pdp_activate;
	char pdp_ip[16];
	uint8_t tmsi_realloc;
	uint8_t release;
	uint8_t rr_cause;
	uint8_t have_gprs;
	uint8_t have_ims;
	uint8_t auth;
	uint8_t iden_imsi_bc;
	uint8_t iden_imei_bc;
	uint8_t iden_imsi_ac;
	uint8_t iden_imei_ac;
	uint8_t cmc_imeisv;
	uint8_t ms_cipher_mask;
	uint32_t ue_cipher_cap;
	uint32_t ue_integrity_cap;
	uint8_t assignment;
	uint8_t assign_complete;
	uint8_t handover;
	uint8_t forced_ho;
	uint8_t use_tmsi;
	uint8_t use_imsi;
	uint8_t use_jump;
	float r_time;
	uint8_t sms_presence;
	uint8_t call_presence;
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
	struct radio_message *new_msg;
	struct sms_meta *sms_list;
	struct session_info *next;
	struct session_info *prev;
	struct gsm_sysinfo_freq cell_arfcns[1024];
	struct cell_info *ci;
	struct rand_state null;
	struct rand_state si5;
	struct rand_state si5bis;
	struct rand_state si5ter;
	struct rand_state si6;
	struct rand_state other_sdcch;
	struct rand_state other_sacch;
	void (*sql_callback)(const char *);
	int output_gsmtap;
} __attribute__((packed));

inline void link_to_msg_list(struct session_info* s, struct radio_message *m);

#define CALLBACK_NONE 0
#define CALLBACK_MYSQL 1
#define CALLBACK_SQLITE 2
#define CALLBACK_CONSOLE 3

#define SET_MSG_INFO(s, ... )  { \
	assert((s)->new_msg); \
	snprintf((s)->new_msg->info, sizeof((s)->new_msg->info), ##__VA_ARGS__); \
};

#define APPEND_MSG_INFO(s, ...) snprintf((s)->new_msg->info+strlen((s)->new_msg->info), sizeof((s)->new_msg->info)-strlen((s)->new_msg->info), ##__VA_ARGS__);

void session_init(unsigned start_sid, int console, const char *gsmtap_target, const char *pcap_target, int callback);
void session_destroy();
struct session_info *session_create(int id, char* name, uint8_t *key, int mcc, int mnc, int lac, int cid, struct gsm_sysinfo_freq *ca);
void session_close(struct session_info *s);
void session_store(struct session_info *s);
void session_reset(struct session_info *s, int forced_release);
void session_free(struct session_info *s);
int session_enumerate();
int session_from_filename(const char *filename, struct session_info *s);

extern uint8_t privacy;
extern uint8_t msg_verbose;
extern uint8_t auto_reset;
extern uint8_t auto_timestamp;
extern struct session_info _s[2];

extern uint32_t now;

#endif
