MYSQL_ARGS = -u root --batch
MYSQL_DB   = test2g_1
DUMMY := $(shell mkdir -p tmp)

COMPARE_TABLES = \
        va \
        sec_params \
        a53_in_use \
        lac_session_type_count \
        attack_component_x4 \
        attack_component \
        risk_tracking \
        risk_intercept \
        risk_impersonation \
        risk_category \

all: new

old: SM = sm_2.4.sql
old: run

new: SM = sm_2.4.new.sql
new: run

clean:
	@rm -f result.dat result.dat.tmp

run: $(addsuffix .tbl, $(addprefix tmp/, $(COMPARE_TABLES)))

tmp/result.log: $(SM)
	@echo -n Generating security scores...
	@mysql $(MYSQL_ARGS) -e "source $(SM);" -e "source data/functions.sql;" -e "source main.sql;" $(MYSQL_DB) > $@.tmp
	@echo OK.

tmp/%.tbl: tests/%.tbl $(SM) tmp/result.log
	@echo -n ...$*...
	@mysql $(MYSQL_ARGS) -e "select * from $*;" $(MYSQL_DB) > $@.tmp
	@diff -q $@.tmp $<
	@mv $@.tmp $@
	@echo OK.

.PHONY: old new clean all run
