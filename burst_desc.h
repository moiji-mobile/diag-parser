#ifndef BURST_DESC_H
#define BURST_DESC_H

#include <stdint.h>

#ifndef __L1CTL_PROTO_H__

#define ARFCN_UPLINK 0x4000
#define BI_FLG_DUMMY    (1<<4)
#define BI_FLG_SACCH    (1<<5)

struct l1ctl_burst_ind {
	uint32_t frame_nr;
	uint16_t band_arfcn;    /* ARFCN + band + ul indicator               */
	uint8_t chan_nr;        /* GSM 08.58 channel number (9.3.1)          */
	uint8_t flags;          /* BI_FLG_xxx + burst_id = 2LSBs             */
	uint8_t rx_level;       /* 0 .. 63 in typical GSM notation (dBm+110) */
	uint8_t snr;            /* Reported SNR >> 8 (0-255)                 */
	uint8_t bits[15];       /* 114 bits + 2 steal bits. Filled MSB first */
} __attribute__((packed));

#endif

#endif

