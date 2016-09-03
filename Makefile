PREFIX ?= /usr

CFLAGS  = \
	-Wall \
	-ggdb \
	-fPIC \
	-I. \
	-I$(PREFIX)/include \

LDFLAGS = \
	-L$(PREFIX)/lib \
	-losmocore \
	-losmogsm \
	-lm

OBJ = \
	address.o \
	assignment.o \
	bit_func.o \
	ccch.o \
	cch.o \
	chan_detect.o \
	crc.o \
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
	viterbi.o \
	lte_nas_eps.o \
	lte_nas_eps_mm.o \
	lte_nas_eps_sm.o \
	lte_nas_eps_info.o

TOOLS = diag_import

ifeq ($(TARGET),host)

CC       = gcc
AR       = ar
TOOLS   += hex_import gsmtap_import analyze.sh
CFLAGS  += -O3

else ifeq ($(TARGET),android)

CC      = $(CROSS_COMPILE)-gcc
AR      = $(CROSS_COMPILE)-ar

CFLAGS += \
	-O2 \
	-fPIE \
	-nostdlib \
	--sysroot=$(SYSROOT) \
	-DUSE_AUTOTIME=1 \
	-DMSG_VERBOSE=1 \
	-DRATE_LIMIT=1 \

LDFLAGS += \
	-fPIE \
	-pie \
	-lcompat \
	--sysroot $(SYSROOT) \
	-L.

LIBRARIES += \
	libcompat.so
else 

ifneq ($(MAKECMDGOALS),clean)
$(error Unsupported target: $(TARGET))
endif
endif

ifeq ($(MYSQL),1)

ifneq ($(TARGET),host)
$(error MYSQL supported for host builds only)
endif

CFLAGS  += -DUSE_MYSQL $(shell mysql_config --cflags)
LDFLAGS += $(shell mysql_config --libs)
OBJ     += mysql_api.o
TOOLS   += db_import
endif

ifeq ($(SQLITE),1)

ifneq ($(TARGET),host)
$(error SQLITE supported for host builds only)
endif

CFLAGS  += -DUSE_SQLITE
LDFLAGS += -lsqlite3
OBJ     += sqlite_api.o
endif

CFLAGS  += $(EXTRA_CFLAGS)

%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(TOOLS)

install: $(TOOLS) $(LIBRARIES) sm_2g.sql sm_3g.sql doc/data/mcc.sql doc/data/mnc.sql doc/data/hlr_info.sql doc/sm.sql
	install -d $(DESTDIR)
	install $^ $(DESTDIR)

sm_2g.sql: doc/sm_2.4.sql
	cpp -DSQLITE -w $< | grep -ve "^#" > $@.tmp
	mv $@.tmp $@

sm_3g.sql: doc/sm_3G_0.9.sql
	cpp -DSQLITE -w $< | grep -ve "^#" > $@.tmp
	mv $@.tmp $@

libmetagsm.so: $(OBJ)
	$(CC) -o $@ $^ -shared -fPIC $(LDFLAGS)

libcompat.so: compat.o
	$(CC) -o $@ $^ -shared -fPIC --sysroot $(SYSROOT) -lc

libmetagsm.a: $(OBJ)
	$(AR) rcs $@ $^

hex_import: hex_import.o libmetagsm.a
	$(CC) -o $@ $^ $(LDFLAGS)

diag_import: diag_import.o libmetagsm.a $(LIBRARIES)
	$(CC) -o $@  diag_import.o libmetagsm.a $(LDFLAGS)

gsmtap_import: gsmtap_import.o libmetagsm.a
	$(CC) -o $@ $^ $(LDFLAGS) -lpcap

db_import: db_import.o libmetagsm.a
	$(CC) -o $@ $^ $(LDFLAGS)

analyze.sh: analyze_header.in cell_info.sql si.sql sms.sql analyze_footer.in
	cat $^ >> $@
	chmod 755 $@

clean:
	@rm -f *.o libmetagsm* *.so
	@rm -f $(TOOLS)

database:
	@rm metadata.db
	@sqlite3 metadata.db < si.sql
	@sqlite3 metadata.db < sms.sql
	@sqlite3 metadata.db < cell_info.sql

.PHONY: all clean database
