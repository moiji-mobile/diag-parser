#ifndef LTE_NAS_EPS_H
#define LTE_NAS_EPS_H

#include "session.h"

/* Marker tag to mark invalid messages in case of failed parsing */
#define NASEPS_INVALID_MSG 0xFF		

/* Maximum number of elements per message */
#define NASEPS_MSG_MAXELM 255



/* 
	GENERIC MESSAGE CONTAINER STRUCTURES
*/

/* Variable length field */
typedef struct 
{
	uint8_t iei;	/* Identifier of the data element (-1 if non existant) */
	unsigned len;	/* Length of the data string */
	uint8_t *data;	/* Pointer to the data of the parsed message  */
	int valid;	/* If set to 1 the field is valid, 0 means valid */
} naseps_msg_string_t;

/* Container for a parsed message */
typedef struct 
{
	uint8_t flags;		/* Security flags (EPS_MM_SEC_*) */
	uint8_t type;		/* Message type (protocol discriminator) */
	uint8_t subtype;	/* Message subtype */
	naseps_msg_string_t elm[NASEPS_MSG_MAXELM];	/* Message elements */
	unsigned n;		/* Number of elements */
	uint8_t *raw;		/* Pointer to the raw message data (wire) */
	unsigned raw_len;	/* Length of the raw message data (wire) */
	uint8_t uplink;		/* Message direction flag 1=Uplink, 0=Downlink */
} naseps_msg_t;

/* 
	MESSAGE SPECIFICATION CONTAINER STRUCTURE
*/

/* Define constants to identify an element type: */
#define ELEMENT_TYPE_1V 1	/* type 1: (V 1/2) vector element (Two nibbles sized vectors in one byte) */
#define ELEMENT_TYPE_1TV 2	/* type 1: (TV 1/2) tag/vector element (Two nibbles first is the tag, second the vector) */
#define ELEMENT_TYPE_2T 3	/* type 2: tag element (one byte tag only) */
#define ELEMENT_TYPE_3V 4	/* type 3: vector element (vector only, length known by spec) */
#define ELEMENT_TYPE_3TV 5	/* type 3: tag/vector element (one byte tag and a fixed length vector) */
#define ELEMENT_TYPE_4LV 6	/* type 4: (LV) length/vector element */
#define ELEMENT_TYPE_4TLV 7	/* type 4: (TLV) tag/length/vector element */
#define ELEMENT_TYPE_6LVE 8	/* type 6: (LV-E) length/vector element */
#define ELEMENT_TYPE_6TLVE 9	/* type 6: (TLV-E) length/vector element */

/* A structure to define a cartain message type */
typedef struct
{
	int msg_type;		/* Message type identifier (protocol discriminator) */
	int msg_subtype;	/* Message subtype identifier */
	int msg_uplink;		/* Uplink flag, 1=UPLINK, 0=Downlink */
	int type[255];		/* Expected field type */
	int len[255];		/* (Max)length of the data field (ignored for Type 1V, Type 1TV and Type 2T) */
	int tag[255];		/* Expected tag (-1 when the message has no tag) */
	int n;			/* Number of elements */
} nas_eps_message_spec;

/* Note: The length setting always encodes the overall length of a message in bytes, this is 
         correspondents directly to the tables which can be found in ETSI TS 124 301. 

         The following types ignore the length parameter:
	 ELEMENT_TYPE_1V, ELEMENT_TYPE_1TV, ELEMENT_TYPE_2T 
	 (Its strongly advised to set the unused length fields to -1)

	 The following types allow for ignoring the (max) length if
         length is set to -1 intentionally:
	 ELEMENT_TYPE_4LV, ELEMENT_TYPE_4TLV

   Note: Fields that do not specify a tag/iei the tag field should
         be set to -1.
*/




/* 
	PRINT FUNCTIONS FOR PRINTING MESSAGES AND ELEMENTS 
*/

/* Print a NAS/EPS variable length epement */
void print_naseps_msg_string(char *identifier, naseps_msg_string_t *element);

/* Print contents of a NAS/EPS message */
void print_naseps_msg(naseps_msg_t *msg);




/* 
	DATA ACCESS TOOLS
*/

/* Get a field by its identifier */
naseps_msg_string_t *get_naseps_msg_field_by_iei(naseps_msg_t *msg, uint8_t iei);

/* Get a field by its position */
naseps_msg_string_t *get_naseps_msg_field_by_pos(naseps_msg_t *msg, uint8_t pos);




/* 
	RAW MESSAGE PARSER
*/

/* Generate a dummy message */
naseps_msg_t *parse_naseps_msg_dummy(uint8_t *raw_message, int len, int type, int subtype, uint8_t uplink);

/* Parse a NAS/EPS message by submitting a message speficication */
naseps_msg_t *parse_naseps_msg_generic(uint8_t *raw_message, int raw_len, nas_eps_message_spec *spec);

/* Dispatch and parse message */
void handle_naseps(struct session_info *s, uint8_t *message, int len);




/*
	CLEANUP FUNCTIONS (free)
*/

/* Cleanup a NAS/EPS variable length epement */
void cleanup_naseps_msg_string(naseps_msg_string_t *element);

/* Cleanup contents of a NAS/EPS message */
void cleanup_naseps_msg(naseps_msg_t *msg);



#endif
