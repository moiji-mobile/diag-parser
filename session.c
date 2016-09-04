#include "session.h"
#include "output.h"
#include "bit_func.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <osmocom/gsm/gsm_utils.h>

#define APPEND(log, msg) snprintf(log+strlen(log), sizeof(log)-strlen(log), "%s", msg);

#ifndef MSG_VERBOSE
#define MSG_VERBOSE 0
#endif /* !MSG_VERBOSE */

uint8_t privacy = 0;
uint8_t msg_verbose = MSG_VERBOSE;
uint8_t auto_reset = 1;

#ifdef USE_AUTOTIME
	uint8_t auto_timestamp = 1;
#else
	uint8_t auto_timestamp = 0;
#endif

static uint8_t output_console = 1;

static uint32_t s_id = 0;
static struct session_info *s_pointer = 0;
pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;

struct session_info _s[2];

uint32_t now = 0;

void session_init(unsigned start_sid, int console, const char *gsmtap_target, const char *pcap_target, int callback)
{
	output_console = console;

	// Reset both domains
	memset(_s, 0, sizeof(_s));

	switch (callback) {
	case CALLBACK_NONE:
		break;
	}

	s_id = start_sid;

	_s[0].id = s_id++;
	_s[1].id = s_id++;
	_s[1].domain = DOMAIN_PS;

	net_init(gsmtap_target, pcap_target);
}

void session_destroy(unsigned *last_sid, unsigned *last_cid)
{
	if (msg_verbose > 1) {
		printf("session_destroy!\n");
	}

	session_reset(&_s[0], 1);
	_s[1].new_msg = NULL;
	session_reset(&_s[1], 1);
	*last_sid = s_id;

	net_destroy();
}

struct session_info *session_create(int id, char* name, uint8_t *key, int mcc, int mnc, int lac, int cid, struct gsm_sysinfo_freq *ca)
{
	struct session_info *ns;

	ns = (struct session_info *) malloc(sizeof(struct session_info));
	memset(ns, 0, sizeof(struct session_info));

	if (id < 0) {
		ns->id = s_id++; 
	} else {
		ns->id = id;
	}

	if (name) {
		strcpy(ns->name, name);
	}

	/* Set timestamp */
	if (auto_timestamp) {
		gettimeofday(&ns->timestamp, 0);
	} else {
		ns->timestamp.tv_sec  = now;
		ns->timestamp.tv_usec = 0;
	}

	if (key) {
		ns->have_key = 1;
		memcpy(ns->key, key, 8);
	}

	/* Copy cell ID */
	ns->mcc = mcc;
	ns->mnc = mnc;
	ns->lac = lac;
	ns->cid = cid;

	/* Store cell ARFCNs */
	if (ca)
		memcpy(ns->cell_arfcns, ca, 1024*sizeof(struct gsm_sysinfo_freq));

	ns->decoded = 1;

	pthread_mutex_lock(&s_mutex);

	if (s_pointer)
		s_pointer->prev = ns;
	ns->next = s_pointer;
	s_pointer = ns;

	pthread_mutex_unlock(&s_mutex);

	return ns;
}

void session_free(struct session_info *s)
{
	assert(auto_reset == 0);
	assert(s != NULL);

	if (s->prev) {
		s->prev->next = s->next;
	}
	if (s->next) {
		s->next->prev = s->prev;
	}
	if (s_pointer == s) {
		s_pointer = s->next;
	}

	free(s);
}

void session_close(struct session_info *s)
{
	assert(s != NULL);

	s->processing = 0;

	/* Attach or update timestamp */
	if (auto_timestamp) {
		gettimeofday(&s->timestamp, NULL);
	} else {
		if (now) {
			s->timestamp.tv_sec = now;
			s->timestamp.tv_usec = 0;
		}
	}

	/* Estimate transaction duration */
	if (s->first_fn <= s->last_fn)
		s->duration = s->last_fn - s->first_fn;
	else
		s->duration = ((s->last_fn + GSM_MAX_FN) - s->first_fn) % GSM_MAX_FN;

	s->duration *= 4.615f;

	/* Estimate authentication delta */
	if (s->auth && s->auth_req_fn && s->auth_resp_fn) {
		if (s->auth_req_fn <= s->auth_resp_fn) {
			s->auth_delta = s->auth_resp_fn - s->auth_req_fn;
		} else {
			s->auth_delta = ((s->auth_resp_fn + GSM_MAX_FN) - s->auth_req_fn) % GSM_MAX_FN;
		}
	}
	s->auth_delta *= 4.615f;

	/* Estimate cipher delta */
	if (s->cipher && s->cm_cmd_fn && s->cm_comp_last_fn) {
		if (s->cm_cmd_fn <= s->cm_comp_last_fn) {
			s->cipher_delta = s->cm_comp_last_fn - s->cm_cmd_fn;
		} else {
			s->cipher_delta = ((s->cm_comp_last_fn + GSM_MAX_FN) - s->cm_cmd_fn) % GSM_MAX_FN;
		}
	}
	s->cipher_delta *= 4.615f;

#if 0
	/* Process neighbour list */
	s->neigh_count = 0;
	for (i=0; i<1024; i++) {
		if (s->neigh_arfcns[i].mask) {
			s->neigh_count++;
		}
	}
#endif

	s->closed = 1;
}

void session_reset(struct session_info *s, int forced_release)
{
	struct session_info old_s;
	struct radio_message *m = NULL;

	if (auto_reset == 0) {
		return;
	}
	if (msg_verbose > 1) {
		printf("Session RESET! domain: %d, forced release: %d\n", s->domain, forced_release);
	}

	assert(s != NULL);

	//Detaching the last attached message to the session.
	if (forced_release) {
		//assert(s->new_msg);
		m = s->new_msg;
	} else {
		if (s->new_msg) { //&& (s->new_msg->flags & MSG_DECODED)
			free(s->new_msg);
		}
		s->new_msg = NULL;
	}

	if (s->started && !s->closed) {
		switch (s->rat) {
		case RAT_GSM:
			printf("RAT: GSM\n");
			break;
		case RAT_UMTS:
			printf("RAT: 3G\n");
			break;
		case RAT_LTE:
			printf("RAT: LTE\n");
			break;
		default:
			printf("RAT: UNKNOWN\n");
		}
		fflush(stdout);
		s->cracked = 1;
		session_close(s);
	}

	memcpy(&old_s, s, sizeof(struct session_info));

	//Set up 's'
	memset(s, 0, sizeof(struct session_info));
	if (old_s.started && old_s.closed) {
		s->id = ++s_id;
	} else {
		s->id = old_s.id;
	}
	s->appid = old_s.appid;
	strncpy(s->name, old_s.name, sizeof(s->name));
	s->domain = old_s.domain;
	if (!auto_timestamp) {
		s->timestamp = old_s.timestamp;
	}
	s->mcc = old_s.mcc;
	s->mnc = old_s.mnc;
	s->lac = old_s.lac;
	if (old_s.rat != RAT_GSM) {
		s->cid = old_s.cid;
	}
	s->arfcn = old_s.arfcn;

	if (forced_release) {
		s->new_msg = m;
	}

	/* Copy information for repeated message detection */
	if (old_s.last_dtap_len) {
		s->last_dtap_len = old_s.last_dtap_len;
		memcpy(s->last_dtap, old_s.last_dtap, old_s.last_dtap_len); 
		s->last_dtap_rat = old_s.last_dtap_rat;
	}

	/* Free allocated memory */

	//TODO remove the check below, it's *expensive*
	if (msg_verbose > 2) {
		printf("session reset (at the end of the function), domain: %d\n", old_s.domain);
	}
}

static uint32_t parse_appid(const char *filename)
{
	char *fn_copy;
	char *ptr;
	char *token;
	uint32_t appid;

	/* We need a copy, tokenizer is not const */
	fn_copy = strdup(filename);

	/* Match file name header */
	ptr = strstr(fn_copy, "2__");
	if (!ptr) {
		return 0;
	}

	/* Skip first part */
	ptr += 3;

	/* Get and ignore first token */
	token = strtok_r(ptr, "_", &ptr);
	if (!token) {
		return 0;
	}

	/* Match App ID string */
	token = strtok_r(0, "_", &ptr);
	if (strlen(token) != 8) {
		return 0;
	}

	/* Parse and return value */
	if (sscanf(token, "%08x", &appid) == 1) {
		return appid;
	}

	return 0;
}

int session_from_filename(const char *filename, struct session_info *s)
{
	char *xgs_ptr;
	char *qdmon_ptr;
	char *ptr;
	char *ptr_copy = NULL;
	char *token;
	struct tm ts;
	struct timeval now;
	int ret;

	/* Try to extract application ID */
	s->appid = parse_appid(filename);

	/* Locate baseband type in filename */
	xgs_ptr = strstr(filename, "_xgs.");
	qdmon_ptr = strstr(filename, "_qdmon.");

	/* Only one string should match */
	if (xgs_ptr) {
		if (qdmon_ptr) {
			goto parse_error;
		} else {
			ptr = xgs_ptr;
		}
	} else {
		if (qdmon_ptr) {
			ptr = qdmon_ptr;
		} else {
			goto parse_error;
		}
	}

	/* We need a copy, tokenizer is not const */
	ptr_copy = strdup(ptr);

	/* Create tokenizer and skip first element */
	token = strtok_r(ptr_copy, ".", &ptr);
	if (!token)
		goto parse_error;

	/* Get phone model (needed for xgs only) */
	token = strtok_r(0, ".", &ptr);
	if (!token) {
		goto parse_error;
	} else {
		// Do model checks for xgs, not really needed for now
	}

	/* Next token */
	token = strtok_r(0, ".", &ptr);
	if (!token)
		goto parse_error;

	ret = strlen(token);

	/* Some model might include version with a dot */
	if (ret == 1 || ret == 2) {
		/* Advance to next token */
		token = strtok_r(0, ".", &ptr);
		if (!token)
			goto parse_error;

		ret = strlen(token);
	}

	/* Check if filename has new IMSI field */
	if (ret == 5 || ret == 6) {
		/* Advance to next token */
		token = strtok_r(0, ".", &ptr);
		if (!token)
			goto parse_error;
	}

	gettimeofday(&now, NULL);
	memset(&ts, 0, sizeof(ts));

	/* Timestamp */
	ret = sscanf(token, "%04d%02d%02d-%02d%02d%02d",
			&ts.tm_year, &ts.tm_mon, &ts.tm_mday,
			&ts.tm_hour, &ts.tm_min, &ts.tm_sec);
	if (ret != 6) {
		fprintf(stderr, "unknown timestamp format %s\n", (token?token:"(null)"));
		goto parse_error;
	} else {
		ts.tm_year -= 1900;
		ts.tm_mon -= 1;
		s->timestamp.tv_sec = mktime(&ts);
		/* Allow timestamps with 12h in advance */
		if (s->timestamp.tv_sec > (now.tv_sec + 43200)) {
			s->timestamp = now;
			fprintf(stderr, "timestamp %s is in the future! using current timestamp\n", token);
		}
	}

	/* Network type */
	token = strtok_r(0, ".", &ptr);
	if (!token)
		goto parse_error;

	if (!strcmp(token, "UMTS") ||
	    !strcmp(token, "3G")||
	    !strcmp(token, "WCDMA")) {
		s->rat = RAT_UMTS;
	} else if (!strcmp(token, "GSM") ||
		   !strcmp(token, "UNKNOWN") ||
		   !strcmp(token, "UNKNWON") ||
		   !strcmp(token, "null")) {
		s->rat = RAT_GSM;
	} else if (!strcmp(token, "LTE")) {
		s->rat = RAT_LTE;
	} else {
		// unknown
		fprintf(stderr, "unknown network type %s\n", token);
		goto parse_error;
	}

	/* Cell ID */
	token = strtok_r(0, ".", &ptr);
	if (!token)
		goto parse_error;

	ret = sscanf(token, "%03hu%03hu-%hx-%x", &s->mcc, &s->mnc, &s->lac, &s->cid);
	if (ret < 4) {
		/* Sometimes LAC/CID is set to "null" */
		s->lac = 65535;
		s->cid = 65535;

		if (ret < 2) {
			/* We couldn't parse even the MCC/MNC */
			fprintf(stderr, "unknown cellid format %s\n", token);
			s->mcc = 65535;
			s->mnc = 65535;
			goto parse_error;
		}
	}

	return 0;

parse_error:
	if (ptr_copy) {
		free(ptr_copy);
	}
	if (auto_timestamp) {
		gettimeofday(&s->timestamp, NULL);
	}
	return -1;
}
