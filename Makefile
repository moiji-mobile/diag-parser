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
	crc.o \
	diag_input.o \
	diag_init.o \
	l3_handler.o \
	output.o \
	session.o

ALL_OBJS = $(OBJ) diag_import.o

TOOLS = diag_parser


all: $(TOOLS)

install: $(TOOLS)
	install -d $(DESTDIR)
	install $^ $(DESTDIR)

libmetagsm.a: $(OBJ)
ifeq ($(V),1)
	$(AR) rcs $@ $^
else
	@echo "AR      $@"
	@$(AR) rcs $@ $^
endif

diag_parser: diag_import.o libmetagsm.a
ifeq ($(V),1)
	$(CC) -o $@  diag_import.o libmetagsm.a $(LDFLAGS) $(LIBS)
else
	@echo "LINK    $@"
	@$(CC) -o $@  diag_import.o libmetagsm.a $(LDFLAGS) $(LIBS)
endif

clean:
	@rm -f *.o libmetagsm* *.so
	@rm -f $(TOOLS)
	@rm -f .d/*.d

.PHONY: all clean

# dependency tracking
DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

COMPILE.c = $(CROSS_COMPILE)$(CC) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
POSTCOMPILE = mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d

%.o : %.c
%.o : %.c $(DEPDIR)/%.d
ifeq ($(V),1)
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)
else
	@echo "CC      $@"
	@$(COMPILE.c) $(OUTPUT_OPTION) $<
	@$(POSTCOMPILE)
endif

$(DEPDIR)/%.d: ;
.PRECIOUS: $(DEPDIR)/%.d

-include $(patsubst %,$(DEPDIR)/%.d,$(basename $(ALL_OBJS)))
