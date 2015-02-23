#include <stdio.h>
#include <osmocom/core/utils.h>

#include "lte_eps.h"

void handle_eps(struct session_info *s, uint8_t *data, unsigned len)
{
	uint8_t sec_header = data[0] >> 4;
	uint8_t proto_disc = data[0] & 0x0f;
	uint8_t msg_type;

	s[0].rat = RAT_LTE;
	s[1].rat = RAT_LTE;

	/* Security header type */
	switch (sec_header) {
	case 0: // Plain
		msg_type = data[1];
		switch (msg_type >> 6) {
		case 1: // EPS MM
			SET_MSG_INFO(s, "EMM plain: %s", osmo_hexdump_nospc(data, len));
			break;
		case 3: // EPS SM
			SET_MSG_INFO(s, "ESM plain: %s", osmo_hexdump_nospc(data, len));
			break;
		default:
			/* Not defined */
			break;
		}
		break;
	case 1: // Integrity protected
		SET_MSG_INFO(s, "EPS integrity: %s", osmo_hexdump_nospc(data, len));
		if (msg_verbose < 2) {
			s->new_msg->flags &= ~MSG_DECODED;
		}
		break;
	case 2: // Integrity and ciphering
		SET_MSG_INFO(s, "EPS ciphered: %s", osmo_hexdump_nospc(data, len));
		if (msg_verbose < 2) {
			s->new_msg->flags &= ~MSG_DECODED;
		}
		break;
	case 3: // Integrity with new EPS context
		SET_MSG_INFO(s, "EPS integrity_new: %s", osmo_hexdump_nospc(data, len));
		if (msg_verbose < 2) {
			s->new_msg->flags &= ~MSG_DECODED;
		}
		break;
	case 4: // Integrity and ciphering with new EPS context
		SET_MSG_INFO(s, "EPS ciphered_new: %s", osmo_hexdump_nospc(data, len));
		if (msg_verbose < 2) {
			s->new_msg->flags &= ~MSG_DECODED;
		}
		break;
	case 12: // Special case for service request
	default: // not used, but treated as 12
		SET_MSG_INFO(s, "EPS service_req: %s", osmo_hexdump_nospc(data, len));
		break;
	}
}

