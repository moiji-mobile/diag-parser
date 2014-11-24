#ifndef CELL_INFO_H
#define CELL_INFO_H

#include <stdint.h>

struct cell_info;

struct session_info;

void cell_init(unsigned start_id, uint32_t unix_time, int callback);
void cell_destroy();
void cell_and_paging_dump(uint32_t timestamp, int forced, int on_destroy);
uint16_t get_mcc(uint8_t *digits);
uint16_t get_mnc(uint8_t *digits);
void handle_sysinfo(struct session_info *s, struct gsm48_hdr *dtap, unsigned len);
void handle_paging1(uint8_t *data, unsigned len);
void handle_paging2(uint8_t *data, unsigned len);
void handle_paging3();

#endif
