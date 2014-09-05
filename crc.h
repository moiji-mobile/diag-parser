/*
 * Copyright 2005 Free Software Foundation, Inc.
 * 
 * This file is part of GNU Radio
 * 
 * GNU Radio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * GNU Radio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU Radio; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */


#ifndef CRC_H
#define CRC_H

#include <stdint.h>

typedef struct
{
	unsigned int crc_size;
	unsigned int data_size;
	unsigned int syn_start;
	int syndrome_reg[40];
} FC_CTX;

int FC_init(FC_CTX *ctx, unsigned int crc_size, unsigned int data_size);
int FC_check_crc(FC_CTX *ctx, unsigned char *input_bits, unsigned char *control_data);

void parity_encode(const uint8_t *data, unsigned dsize, const uint8_t *poly,
		   uint8_t *parity, unsigned psize);

int parity_check(const uint8_t *data, unsigned dsize, const uint8_t *poly,
		 const uint8_t *remainder, unsigned psize);

#endif
