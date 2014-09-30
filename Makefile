ifeq ($(DB),mysql)
CPP_FLAGS = -DMYSQL
DB_NAME   = test2g_1
DB_ENGINE = mysql -u root --batch
else
ifeq ($(DB),sqlite)
CPP_FLAGS = -DSQLITE
DB_NAME   ?= data/gsmmap_full.sqlite
DB_ENGINE = sqlite3
else
$(error No DB selected!)
endif
endif

DUMMY := $(shell mkdir -p tmp)

COMPARE_TABLES = \
        attack_component \
        risk_impersonation \
        risk_category \
        risk_intercept \
        risk_tracking \
        attack_component_x4 \
        lac_session_type_count \
        sec_params \
        va \

all: new

old: SM = sm_2.4.sql
new: SM = sm_2.4.new.sql
old new: run

clean:
	@rm -f result.dat result.dat.tmp
	@rm -rf tmp
	@cat cleanup.sql | $(DB_ENGINE) $(DB_NAME)

run: $(addsuffix .tbl, $(addprefix tmp/, $(COMPARE_TABLES)))

tmp/result.log: *.sql
	@echo Generating security score $(SM)...
	cpp $(CPP_FLAGS) -w $(SM) | grep -ve "^#" > $@.tmp
	time cpp $(CPP_FLAGS) -w $(SM) | grep -ve "^#" | $(DB_ENGINE) $(DB_NAME)
	@mv $@.tmp $@
	@echo OK.

tmp/%.tbl: tests/%.tbl tmp/result.log
	@echo -n ...$*...
	@echo "select * from $*;" | $(DB_ENGINE) $(DB_NAME) > $@.tmp
	@diff -q $@.tmp $<
	@mv $@.tmp $@
	@echo OK.

.PHONY: old new clean all run
