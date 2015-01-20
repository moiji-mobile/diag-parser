CC      = gcc
CFLAGS  = -Wall -O3 -ggdb -I. -I/usr/include/asn1c -fPIC $(EXTRA_CFLAGS)
LDFLAGS = -losmocore -losmogsm -lasn1c -lm -losmo-asn1-rrc $(EXTRA_LDFLAGS)

OBJ = \
	address.o \
	assignment.o \
	bit_func.o \
	ccch.o \
	cch.o \
	chan_detect.o \
	crc.o \
	umts_rrc.o \
	diag_input.o \
	gprs.o \
	gsm_interleave.o \
	cell_info.o \
	l3_handler.o \
	output.o \
	process.o \
	punct.o \
	rand_check.o \
	rlcmac.o \
	sch.o \
	session.o \
	sms.o \
	tch.o \
	viterbi.o

TOOLS = diag_import hex_import gsmtap_import analyze.sh

ifeq ($(MYSQL),1)
CFLAGS  += -DUSE_MYSQL $(shell mysql_config --cflags)
LDFLAGS += $(shell mysql_config --libs)
OBJ     += mysql_api.o
TOOLS   += db_import
endif

ifeq ($(SQLITE),1)
CFLAGS  += -DUSE_SQLITE
LDFLAGS += -lsqlite3
OBJ     += sqlite_api.o
endif

%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(TOOLS)

libmetagsm.so: $(OBJ)
	$(CC) -o $@ $^ -shared -fPIC $(LDFLAGS)

libmetagsm.a: $(OBJ)
	ar rcs $@ $^

hex_import: hex_import.o libmetagsm.a
	$(CC) -o $@ $^ $(LDFLAGS)

diag_import: diag_import.o libmetagsm.a
	$(CC) -o $@ $^ $(LDFLAGS)

gsmtap_import: gsmtap_import.o libmetagsm.a
	$(CC) -o $@ $^ $(LDFLAGS) -lpcap

db_import: db_import.o libmetagsm.a
	$(CC) -o $@ $^ $(LDFLAGS)

analyze.sh: analyze_header.in cell_info.sql si.sql sms.sql analyze_footer.in
	cat $^ >> $@
	chmod 755 $@

clean:
	@rm -f *.o libmetagsm* *.so
	@rm -f db_import gsmtap_import diag_import hex_import

database:
	@rm metadata.db
	@sqlite3 metadata.db < si.sql
	@sqlite3 metadata.db < sms.sql
	@sqlite3 metadata.db < cell_info.sql

.PHONY: all clean database
