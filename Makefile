CC=gcc
CFLAGS=-O2 -ggdb -I. -I/usr/share/asn1c -fPIC $(shell mysql_config --cflags)
LDFLAGS=-losmocore -losmogsm -lasn1c -losmo-asn1-rrc -lsqlite3 $(shell mysql_config --libs)
OBJ =	address.o assignment.o bit_func.o ccch.o cch.o chan_detect.o crc.o \
	umts_rrc.o diag_input.o gprs.o gsm_interleave.o cell_info.o \
	l3_handler.o output.o process.o punct.o rand_check.o rlcmac.o \
	sch.o session.o sms.o tch.o viterbi.o

%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

all: libmetagsm diag_import

libmetagsm: $(OBJ) sqlite_api.o mysql_api.o
	ar rcs $@.a $^
	gcc -o $@.so $^ -shared -fPIC $(LDFLAGS)

libmetagsm-sqlite: $(OBJ) sqlite_api.o
	ar rcs $@.a $^
	gcc -o $@.so $^ -shared -fPIC $(LDFLAGS)

libmetagsm-mysql: $(OBJ) mysql_api.o
	ar rcs $@.a $^
	gcc -o $@.so $^ -shared -fPIC $(LDFLAGS)

diag_import: diag_import.o libmetagsm.a
	gcc -o $@ $^ $(LDFLAGS)

clean:
	@rm -f *.o diag_import libmetagsm*

database:
	@rm metadata.db
	@sqlite3 metadata.db < si.sql
