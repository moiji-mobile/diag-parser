CFLAGS  = \
	-Wall \
	-fPIC \
	-I. \
	`pkg-config --cflags libosmogsm`

LIBS = \
	`pkg-config --libs libosmogsm`

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


CC      = $(CROSS_COMPILE)gcc
AR      = $(CROSS_COMPILE)ar


%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

all: $(TOOLS)

install: $(TOOLS)
	install -d $(DESTDIR)
	install $^ $(DESTDIR)

libmetagsm.a: $(OBJ)
	$(AR) rcs $@ $^

diag_import: diag_import.o libmetagsm.a
	$(CC) -o $@  diag_import.o libmetagsm.a $(LDFLAGS) $(LIBS)

clean:
	@rm -f *.o libmetagsm* *.so
	@rm -f $(TOOLS)

.PHONY: all clean
