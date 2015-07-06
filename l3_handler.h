#ifndef _L3_HANDLER_H
#define _L3_HANDLER_H

#include "process.h"
#include "session.h"

void handle_lai(struct session_info *s, uint8_t *data, int cid);
void handle_mi(struct session_info *s, uint8_t *data, uint8_t len, uint8_t new_tmsi);
void handle_cc(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint8_t ul);
void handle_rr(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint32_t fn);
void handle_mm(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint32_t fn);
void handle_ss(struct session_info *s, struct gsm48_hdr *dtap, unsigned len);
void handle_gmm(struct session_info *s, struct gsm48_hdr *dtap, unsigned len);
void handle_sm(struct session_info *s, struct gsm48_hdr *dtap, unsigned len);
void handle_dtap(struct session_info *s, uint8_t *msg, size_t len, uint32_t fn, uint8_t ul);
void handle_lapdm(struct session_info *s, struct lapdm_buf *mb, uint8_t *msg, unsigned len, uint32_t fn, uint8_t ul);
void handle_radio_msg(struct session_info *s, struct radio_message *m);
unsigned encapsulate_lapdm(uint8_t *data, unsigned len, uint8_t ul, uint8_t sacch, uint8_t **output);
struct radio_message * new_l2(uint8_t *data, uint8_t len, uint8_t rat, uint8_t domain, uint32_t fn, uint8_t ul, uint8_t flags);
struct radio_message * new_l3(uint8_t *data, uint8_t len, uint8_t rat, uint8_t domain, uint32_t fn, uint8_t ul, uint8_t flags);

#endif
