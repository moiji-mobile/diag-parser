#include <stdio.h>
#include <string.h>
#include <osmocom/core/utils.h>
#include "lte_nas_eps.h"
#include "lte_nas_eps_mm.h"
#include "lte_nas_eps_sm.h"
#include "lte_nas_eps_info.h"
#include <assert.h>

/* 
	PARSER FUNCTIONS FOR SINGLE ELEMENTS 
*/

/* Parse a type 1 vector element (Two nibbles sized vectors in one byte) */
static int parse_naseps_type1v(uint8_t *msg, int msg_len, naseps_msg_string_t *element1, naseps_msg_string_t *element2)
{
	element1->iei = -1;
	element1->len = 0;
	element1->data = NULL;
	element1->valid = 0;
	element2->iei = -1;
	element2->len = 0;
	element2->data = NULL;
	element2->valid = 0;

	/* Length check */
	if(msg_len < 1)
		return 0;

	element1->len = 1;
	element2->len = 1;
	element1->iei = -1;
	element2->iei = -1;
	element1->data = (uint8_t*) malloc(1);
	assert(element1->data);
	element2->data = (uint8_t*) malloc(1);
	assert(element2->data);
	element1->data[0] = msg[0] & 0x0F;
	element2->data[0] = (msg[0]>>4) & 0x0F;
	element1->valid = 1;
	element2->valid = 1;

	return 1;
}

/* Parse a type 1 tag/vector element (Two nibbles first is the tag, second the vector) */
static int parse_naseps_type1tv(uint8_t *msg, int msg_len, naseps_msg_string_t *element, int expected_tag)
{
	int tag;
	tag = (msg[0]>>4) & 0x0F;

	element->iei = expected_tag;
	element->len = 0;
	element->data = NULL;
	element->valid = 0;

	/* Length check */
	if(msg_len < 1)
		return 0;

	/* Tag check */
	if(tag != expected_tag)
		return 0;

	element->len = 1;
	element->iei = tag;
	element->data = (uint8_t*) malloc(1);
	assert(element->data);
	element->data[0] = msg[0] & 0x0F;
	element->valid = 1;

	return 1;
}

/* Parse a type 2 tag element (entire filed consits of one byte tag only) */
static int parse_naseps_type2t(uint8_t *msg, int msg_len, naseps_msg_string_t *element, int expected_tag)
{
	int tag;
	tag = msg[0];

	element->iei = expected_tag;
	element->len = 0;
	element->data = NULL;
	element->valid = 0;

	/* Length check */
	if(msg_len < 1)
		return 0;

	/* Tag check */
	if(tag != expected_tag)
		return 0;

	element->len = 0;
	element->iei = tag;
	element->data = NULL;
	element->valid = 1;

	return 1;
}

/* Parse a type 3 vector element (vector only, length known by spec) */
static int parse_naseps_type3v(uint8_t *msg, int msg_len, int len, naseps_msg_string_t *element)
{
	element->iei = -1;
	element->len = 0;
	element->data = NULL;
	element->valid = 0;

	/* Length check */
	if(msg_len < len)
		return 0;

	element->len = len;
	element->iei = -1;
	element->data = (uint8_t*) malloc(element->len);
	assert(element->data);
	memcpy(element->data, msg, len);
	element->valid = 1;

	return element->len;
}

/* Parse a type 3 tag/vector element (one byte tag only) */
static int parse_naseps_type3tv(uint8_t *msg, int msg_len, int len, naseps_msg_string_t *element, int expected_tag)
{
	int tag;
	tag = msg[0];

	element->iei = expected_tag;
	element->len = 0;
	element->data = NULL;
	element->valid = 0;

	/* Tag check */
	if(tag != expected_tag)
		return 0;

	/* Length check */
	if(msg_len < len)
		return 0;

	element->len = len-1;
	element->iei = tag;
	element->data = (uint8_t*) malloc(element->len);
	assert(element->data);
	memcpy(element->data, msg+1, len);
	element->valid = 1;

	return element->len + 1;
}

/* Parse a type 4 length/vector element */
static int parse_naseps_type4lv(uint8_t *msg, int msg_len, naseps_msg_string_t *element, int expected_len)
{
	int len;
	len = msg[0];

	element->iei = -1;
	element->len = 0;
	element->data = NULL;
	element->valid = 0;

	/* Length check */
	if(msg_len < len+1)
		return 0;
	if((len > expected_len)&&(expected_len != -1))
		return 0;
	if(len <= 0)
		return 0;

	element->len = len;
	element->iei = -1;
	element->data = (uint8_t*) malloc(element->len);
	assert(element->data);
	memcpy(element->data, msg+1, element->len);
	element->valid = 1;

	return element->len + 1;
}

/* Parse a type 4 tag/length/vector element */
static int parse_naseps_type4tlv(uint8_t *msg, int msg_len, naseps_msg_string_t *element, int expected_tag, int expected_len)
{
	int tag;
	int len;
	tag = msg[0];
	len = msg[1];

	element->iei = expected_tag;
	element->len = 0;
	element->data = NULL;
	element->valid = 0;

	/* Length check */
	if(msg_len < len+2)
		return 0;
	if((len > expected_len)&&(expected_len != -1))
		return 0;
	if(len <= 0)
		return 0;

	/* Tag check */
	if(tag != expected_tag)
		return 0;

	element->len = len;
	element->iei = tag;
	element->data = (uint8_t*) malloc(element->len);
	assert(element->data);
	memcpy(element->data, msg+2, element->len);
	element->valid = 1;

	return element->len + 2;
}

/* Parse a type 6 length/vector element */
static int parse_naseps_type6lve(uint8_t *msg, int msg_len, naseps_msg_string_t *element, int expected_len)
{
	int len;
	len = msg[1];
	len |= (msg[0] << 8);

	element->iei = -1;
	element->len = 0;
	element->data = NULL;
	element->valid = 0;

	/* Length check */
	if(msg_len < len+2)
		return 0;
	if((len > expected_len)&&(expected_len != -1))
		return 0;
	if(len <= 0)
		return 0;

	element->len = len;
	element->iei = -1;
	element->data = (uint8_t*) malloc(element->len);
	assert(element->data);
	memcpy(element->data, msg+2, element->len);
	element->valid = 1;

	return element->len + 2;
}

/* Parse a type 6 tag/length/vector element */
static int parse_naseps_type6tlve(uint8_t *msg, int msg_len, naseps_msg_string_t *element, int expected_tag, int expected_len)
{
	int tag;
	int len;
	tag = msg[0];
	len = msg[2];
	len |= (msg[1] << 8);

	element->iei = expected_tag;
	element->len = 0;
	element->data = NULL;
	element->valid = 0;

	/* Length check */
	if(msg_len < len+3)
		return 0;
	if((len > expected_len)&&(expected_len != -1))
		return 0;
	if(len <= 0)
		return 0;

	/* Tag check */
	if(tag != expected_tag)
		return 0;

	element->len = len;
	element->iei = tag;
	element->data = (uint8_t*) malloc(element->len);
	assert(element->data);
	memcpy(element->data, msg+3, element->len);
	element->valid = 1;

	return element->len + 3;
}




/* 
	PRINT FUNCTIONS FOR PRINTING MESSAGES AND ELEMENTS 
*/

/* Print a NAS/EPS variable length epement */
void print_naseps_msg_string(char *identifier, naseps_msg_string_t *element)
{
	if(identifier)
		printf(" %s=",identifier);
	else
		printf(" ");
	
	printf("naseps_msg_string_t{");

	if(element->iei != -1)
		printf("iei=%i (0x%02x), ",element->iei,element->iei & 0xFF);

	if(element->data != NULL)
		printf("len=%i, data=%s ",element->len, osmo_hexdump_nospc((uint8_t*)element->data, element->len));
	else
		printf("len=%i, data=NULL ",element->len);

	printf("valid=%i}\n",element->valid);
}

/* Print contents of a NAS/EPS message */
void print_naseps_msg(naseps_msg_t *msg)
{
	int i;
	printf(" naseps_msg_t\n {\n");
	printf(" n=%i\n",msg->n);
	printf(" type=%i (0x%02x)\n",msg->type,msg->type);
	printf(" subtype=%i (0x%02x)\n",msg->subtype,msg->subtype);
	printf(" raw_len=%i\n", msg->raw_len);
	if(msg->raw_len > 0)
		printf(" raw=%s\n",osmo_hexdump_nospc((uint8_t*)msg->raw, msg->raw_len));
	else
		printf(" raw=(no data)\n");

	/* Check if the message is invalid for some reason */
	if(msg->type == NASEPS_INVALID_MSG)
	{
		printf(" (Unable to display contents of this message)\n }\n");
		return;
	}

	/* Dump message content */
	for(i=0;i<msg->n;i++)
		print_naseps_msg_string(0,&msg->elm[i]);

	printf(" }\n");
}



/* 
	DATA ACCESS TOOLS
*/

/* Get a field by its identifier */
naseps_msg_string_t *get_naseps_msg_field_by_iei(naseps_msg_t *msg, uint8_t iei)
{
	int i;

	/* Loop through all possible fields */
	for(i=0;i<msg->n;i++)
	{
		/* Get the data when the field exists and the identifier matches */
		if(msg->elm[i].iei==iei)
		{
			return &(msg->elm[i]);
		}
	}
	return NULL;
}


/* Get a field by its position */
naseps_msg_string_t *get_naseps_msg_field_by_pos(naseps_msg_t *msg, uint8_t pos)
{
	if(pos && (pos < msg->n))
	{
		if (msg->elm[pos].valid)
		{
			return &(msg->elm[pos]);
		}
	}
	
	return NULL;
}



/* 
	RAW MESSAGE PARSER
*/


/* Generate a dummy message */
naseps_msg_t *parse_naseps_msg_dummy(uint8_t *raw_message, int len, int type, int subtype, uint8_t uplink)
{
	nas_eps_message_spec spec;

	/* Setup specification */
	spec.n=0;
	spec.msg_type=type;
	spec.msg_subtype=subtype;
	spec.msg_uplink=uplink;
	
	/* Parse message */
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Parse a NAS/EPS message by submitting a message speficication */
naseps_msg_t *parse_naseps_msg_generic(uint8_t *raw_message, int raw_len, nas_eps_message_spec *spec)
{
	int i;
	int e=0;
	int len;
	naseps_msg_t *msg;

	/* Create an empty message body */
	msg = (naseps_msg_t*) malloc(sizeof(naseps_msg_t));
	assert(msg);
	memset(msg,0,sizeof(naseps_msg_t));

	/* Create a copy of the message data (allows for re use of the input buffers) */
	msg->raw=(uint8_t *) malloc(raw_len);
	assert(msg->raw);
	memcpy(msg->raw, raw_message, raw_len);
	msg->raw_len=raw_len;	

	for(i=0;i<spec->n;i++)
	{
		switch(spec->type[i])
		{
			/* type 1 vector element (Two nibbles sized vectors in one byte) */
			case ELEMENT_TYPE_1V:
				len = parse_naseps_type1v(raw_message, raw_len, &msg->elm[e],&msg->elm[e+1]);
				e+=2;
			break;
			/* type 1 tag/vector element (Two nibbles first is the tag, second the vector) */
			case ELEMENT_TYPE_1TV:
				len = parse_naseps_type1tv(raw_message, raw_len, &msg->elm[e], spec->tag[i]);
				e++;
			break;
			/* type 2 tag element (one byte tag only) */
			case ELEMENT_TYPE_2T:
				len = parse_naseps_type2t(raw_message, raw_len, &msg->elm[e], spec->tag[i]);
				e++;
			break;
			/* type 3 vector element (vector only, length known by spec) */	
			case ELEMENT_TYPE_3V:
				len = parse_naseps_type3v(raw_message, raw_len, spec->len[i], &msg->elm[e]);
				e++;
			break;
			/* type 3 tag/vector element (one byte tag only) */	
			case ELEMENT_TYPE_3TV:
				len = parse_naseps_type3tv(raw_message, raw_len, spec->len[i], &msg->elm[e], spec->tag[i]);
				e++;
			break;
			/* type 4 length/vector element */	
			case ELEMENT_TYPE_4LV:
				len = parse_naseps_type4lv(raw_message, raw_len, &msg->elm[e], spec->len[i]);
				e++;
			break;
			/* type 4 tag/length/vector element */	
			case ELEMENT_TYPE_4TLV:
				len = parse_naseps_type4tlv(raw_message, raw_len, &msg->elm[e], spec->tag[i], spec->len[i]);
				e++;
			break;
			/* type 6: (LV-E) length/vector element */
			case ELEMENT_TYPE_6LVE:
				len = parse_naseps_type6lve(raw_message, raw_len, &msg->elm[e], spec->len[i]);
				e++;
			break;
			/* type 6 tag/length/vector element */	
			case ELEMENT_TYPE_6TLVE:
				len = parse_naseps_type6tlve(raw_message, raw_len, &msg->elm[e], spec->tag[i], spec->len[i]);
				e++;
			break;
			default:
				printf("Error: Invalid element type specified!\n");
				exit(1);
			break;
		}

		/* Move forward to the next element */
		raw_message += len;
		raw_len -= len; 
	}
	
	msg->type=spec->msg_type;	/* Set the desired message type */
	msg->subtype=spec->msg_subtype;	/* Set the desired message subtype */
	msg->n=e;			/* Set the number of elements we were able to detect */
	msg->uplink=spec->msg_uplink;	/* Set uplink flag as specified in the specification */

	return msg;
}


/* Cleanup a NAS/EPS variable length epement */
void cleanup_naseps_msg_string(naseps_msg_string_t *element)
{
	/* Free allocated memory */
	if(element->data != NULL)
		free(element->data);

	/* Zero out the memory occupied by the data structure */
	memset(element,0,sizeof(naseps_msg_string_t));
}


/* Cleanup contents of a NAS/EPS message */
void cleanup_naseps_msg(naseps_msg_t *msg)
{
	int i;

	/* cleanup allocated elements */
	for(i = 0; i < msg->n; i++)
		cleanup_naseps_msg_string(&msg->elm[i]);

	/* Free raw data */
	if(msg->raw != NULL)
		free(msg->raw);

	/* Zero out the memory occupied by the data structure */
	memset(msg,0,sizeof(naseps_msg_t));
}


/* Parse and dispatch message */
void handle_naseps(struct session_info *s, uint8_t *message, int len)
{
	uint8_t protocol_discriminator;	
	naseps_msg_t *msg = NULL;
	uint8_t uplink_flag;

	/* Extract protocol discriminator */
	protocol_discriminator = message[0] & 0x0F;

	/* Fetch uplink flag from ession_info structure */
	/* TODO: Probably not the right place to do that here! 
		 the caller should take care himself! */
	uplink_flag = !!(s->new_msg->bb.arfcn[0] & ARFCN_UPLINK);


	/* Parse accordingly */
	switch(protocol_discriminator)
	{
		case PROTOCOL_EPS_MM: 
			msg = parse_naseps_mm_msg(message, len, uplink_flag);
			break;
		case PROTOCOL_EPS_SM: 
			msg = parse_naseps_sm_msg(message, len, uplink_flag);
			break;
		default:
			msg = NULL;
			break;
	}

	if (msg) {
#ifndef TESTBENCH
		naseps_set_msg_info(s, msg);
#endif
		cleanup_naseps_msg(msg);
	}
}

