CC=/home/luca/Downloads/android-ndk-r10/ndk-build
CFLAGS=-O2 -ggdb -I. -I/usr/share/asn1c -fPIC
LDFLAGS=-losmocore -losmogsm -lasn1c -lm -losmo-asn1-rrc
OBJ =	address.o assignment.o bit_func.o ccch.o cch.o chan_detect.o crc.o \
	umts_rrc.o diag_input.o gprs.o gsm_interleave.o cell_info.o \
	l3_handler.o output.o process.o punct.o rand_check.o rlcmac.o \
	sch.o session.o sms.o tch.o viterbi.o

%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

all: libmetagsm diag_import gsmtap_import

libmetagsm: $(OBJ)
	ar rcs $@.a $^
	$(CC) -o $@.so $^ -shared -fPIC $(LDFLAGS)

diag_import: diag_import.o libmetagsm.a
	$(CC) -o $@ $^ $(LDFLAGS)

gsmtap_import: gsmtap_import.o libmetagsm.a
	gcc -o $@ $^ $(LDFLAGS) -lpcap

clean:
	@rm -f *.o diag_import libmetagsm*

database:
	@rm metadata.db
	@sqlite3 metadata.db < si.sql
