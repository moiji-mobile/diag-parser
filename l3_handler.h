#ifndef _L3_HANDLER_H
#define _L3_HANDLER_H

#include "process.h"
#include "session.h"

void handle_cc(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint8_t ul);
void handle_rr(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint32_t fn);
void handle_mm(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint32_t fn);
void handle_ss(struct session_info *s, struct gsm48_hdr *dtap, unsigned len);
void handle_gmm(struct session_info *s, struct gsm48_hdr *dtap, unsigned len);
void handle_sm(struct session_info *s, struct gsm48_hdr *dtap, unsigned len);
void handle_dtap(struct session_info *s, uint8_t *msg, size_t len, uint32_t fn, uint8_t ul);
void handle_lapdm(struct session_info *s, struct lapdm_buf *mb, uint8_t *msg, unsigned len, uint32_t fn, uint8_t ul);

#endif
