#ifndef CELL_INFO_H
#define CELL_INFO_H

struct cell_info;

struct session_info;

void cell_init(unsigned start_id, int callback);
void cell_destroy();
void cell_and_paging_dump();
void paging_inc(int pag_type);
int get_mcc(uint8_t *digits);
int get_mnc(uint8_t *digits);
void handle_sysinfo(struct session_info *s, struct gsm48_hdr *dtap, unsigned len, uint32_t fn);

#endif
