#ifndef __DIAG_STRUCTS_H__
#define __DIAG_STRUCTS_H__

uint16_t get_arfcn_from_arfcn_and_band(uint16_t val)
{
	//uint16_t  arfcn:12;
	//uint16_t  band:4;
	uint16_t val_a = val >> 8;
	uint16_t val_b = val & 0xff;
	val = val_a + (val_b << 8);

	//bottom 12 (yup!!)
	return val & 0x0fff;
}

uint8_t get_band_from_arfcn_and_band(uint16_t val)
{
	//uint16_t  arfcn:12;
	//uint16_t  band:4;
	uint16_t val_a = val >> 8;
	uint16_t val_b = val & 0xff;
	val = val_a + (val_b << 8);

	//top 4(yup!)
	return val >> 12;
}


/*********************************************************/

struct  burst_metrics  {
	uint32_t  frame_number;
	uint16_t  arfcn_and_band;
	uint32_t  rssi;
	int16_t  rx_power;
	int16_t  dc_offset___i_channel;
	int16_t  dc_offset___q_channel;
	int16_t  frequency_offset_estimate;
	uint16_t  timing_offset_estimate;
	uint16_t  snr_estimate;
	uint8_t   gain_state;
} __attribute__((packed));

//cmd: 0x506C
struct  gsm_l1_burst_metrics  {
	uint8_t   channel;
	struct burst_metrics metrics[4];
} __attribute__((packed));

/*********************************************************/
struct  bsic  {
	uint8_t   bcc : 3; // NOTE: sub-byte
	uint8_t   ncc : 3; // NOTE: sub-byte
	uint8_t Pad: 2;
} __attribute__((packed));

struct  surrounding_cell  {
	uint16_t  bcch_arfcn_and_band;
	int16_t  rx_power;
	uint8_t   bsic_known;
	struct bsic bsic_this;
	uint32_t  frame_number_offset;
	uint16_t  time_offset;
} __attribute__((packed));

//cmd: 0x5071
struct  gsm_l1_surround_cell_ba_list  {
	uint8_t   cell_count;
	struct surrounding_cell surr_cells[0];
} __attribute__((packed));

/*********************************************************/

//cmd: 0x5076
struct  gsm_l1_txlev_timing_advance  {
	uint16_t arfcn_and_band;
	uint8_t   tx_power_level;
	uint8_t   timing_advance;
} __attribute__((packed));

/*********************************************************/

struct  cell  {
	uint16_t arfcn_and_band;
	int16_t  rx_power;
} __attribute__((packed));

//cmd: 0x507B
struct  gsm_l1_neighbor_cell_auxiliary_measurments  {
	uint8_t   cell_count;
	struct cell cells[0];
} __attribute__((packed));

/*********************************************************/

struct  monitor_record  {
	uint32_t  frame_number;
	uint16_t arfcn_and_band;
	uint16_t  rx_power;
	uint32_t  rssi;
	uint8_t   gain_state;
} __attribute__((packed));

//cmd: 0x5082
struct  gsm_monitor_bursts_v2  {
	uint32_t  number_of_records;
	struct monitor_record records[0];
} __attribute__((packed));

/*********************************************************/

struct  neighbor  {
	uint16_t  neighbor_cell_bcch_arfcn_and_band;
	uint16_t  neighbor_cell_pbcch_arfcn_and_band;
	uint8_t   hierarchy_cell_structure_priority;
	uint8_t   neighbor_cell_rx_level_average;
	uint32_t  neighbor_cell___computed_c1_value;
	uint32_t  neighbor_cell___computed_c2_value;
	uint32_t  neighbor_cell___computed_c31_value;
	uint32_t  neighbor_cell___computed_c32_value;
	uint8_t   neighbor_five_second_timer;
	uint8_t   neighbor_cell_reselection;
	uint8_t   serving_ra;
} __attribute__((packed));

//0x51FC
struct  gprs_grr_cell_reselection_measurements  {
	uint16_t  serving_bcch_arfcn_and_band;
	uint16_t  serving_pbcch_arfcn_and_band;
	uint8_t   serving_priority_class;
	uint8_t   serving_rx_level_average;
	uint32_t  serving_cell___computed_c1_value;
	uint32_t  serving_cell___computed_c2_value;
	uint32_t  serving_cell___computed_c31_value;
	uint32_t  serving_cell___computed_c32_value;
	uint8_t   serving_five_second_timer;
	uint8_t   serving_cell_reselection;
	uint8_t   serving_cell_recent_reselection;
	uint8_t   neighboring_6_strongest_cells_count;
	struct neighbor neigbors[6];
} __attribute__((packed));

#endif //__DIAG_STRUCTS_H__
