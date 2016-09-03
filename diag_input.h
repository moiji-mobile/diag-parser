#ifndef DIAG_INPUT_H
#define DIAG_INPUT_H

#include <stdint.h>
#include <stdio.h>

void diag_init(unsigned start_sid, unsigned start_cid, const char *gsmtap_target, const char *pcap_target, char *filename, uint32_t appid);
void diag_set_log(FILE* file);
void diag_set_filename(char *filename);
void diag_set_appid(uint32_t appid);
void handle_diag(uint8_t *msg, unsigned len);
void diag_destroy();

#endif
