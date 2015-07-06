#include <stdio.h>
#include <string.h>
#include <osmocom/core/utils.h>

#include "lte_nas_eps.h"
#include "lte_nas_eps_sm.h"

/* Dispatch and parse a regular NAS/EPS message */
naseps_msg_t *parse_naseps_sm_msg(uint8_t *raw_message, int len, uint8_t uplink)
{
	naseps_msg_t* msg;
	uint8_t message_type;

	/* Lookup the message identity (Caution: HACK) */
	if(len >= 3)
		message_type = raw_message[2];
	else
		return NULL;

	/* Look at the protocol discriminator and decide what to do */
	switch(message_type)
	{
		/* Return a message marked as unknown */
		default:
			msg = parse_naseps_msg_dummy(raw_message, len, PROTOCOL_EPS_SM, message_type & 0xFF, uplink);
		break;
	}

	return msg;
}
