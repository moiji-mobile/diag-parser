CC=gcc
CFLAGS=-O2 -ggdb -I. -I/usr/include/asn1c -fPIC $(EXTRA_CFLAGS)
LDFLAGS=-losmocore -losmogsm -lasn1c -lm -losmo-asn1-rrc $(EXTRA_LDFLAGS)
OBJ=address.o assignment.o bit_func.o ccch.o cch.o chan_detect.o crc.o \
	umts_rrc.o diag_input.o gprs.o gsm_interleave.o cell_info.o \
	l3_handler.o output.o process.o punct.o rand_check.o rlcmac.o \
	sch.o session.o sms.o tch.o viterbi.o

# Host build
CFLAGS+=-DUSE_MYSQL -DUSE_SQLITE $(shell mysql_config --cflags)
LDFLAGS+=$(shell mysql_config --libs) -lsqlite3
OBJ+=mysql_api.o sqlite_api.o

# Database config for r2
#CFLAGS+=-DMYSQL_USER=\"root\" -DMYSQL_PASS=\"moth*echo5Sigma\" -DMYSQL_DBNAME=\"session_meta_test\"

%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

all: diag_import gsmtap_import db_import

libmetagsm.so: $(OBJ)
	$(CC) -o $@ $^ -shared -fPIC $(LDFLAGS)

libmetagsm.a: $(OBJ)
	ar rcs $@ $^

diag_import: diag_import.o libmetagsm.a
	$(CC) -o $@ $^ $(LDFLAGS)

gsmtap_import: gsmtap_import.o libmetagsm.a
	gcc -o $@ $^ $(LDFLAGS) -lpcap

db_import: db_import.o libmetagsm.a
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	@rm -f *.o libmetagsm* *.so
	@rm -f db_import gsmtap_import diag_import

database:
	@rm metadata.db
	@sqlite3 metadata.db < si.sql
	@sqlite3 metadata.db < sms.sql
	@sqlite3 metadata.db < cell_info.sql
