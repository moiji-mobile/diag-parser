MYSQL_ARGS = -u root --batch
MYSQL_DB   = test2g_1
DUMMY := $(shell mkdir -p tmp)

COMPARE_TABLES = \
        va \
        sec_params \
        lac_session_type_count \
        attack_component_x4 \
        attack_component \
        risk_tracking \
        risk_intercept \
        risk_impersonation \
        risk_category \

all: new

old: SM = sm_2.4.sql
new: SM = sm_2.4.new.sql
old new: run

clean:
	@rm -f result.dat result.dat.tmp
	@rm -rf tmp

run: $(addsuffix .tbl, $(addprefix tmp/, $(COMPARE_TABLES)))

tmp/result.log: *.sql
	@echo Generating security score $(SM)...
	@time mysql $(MYSQL_ARGS) -e "source $(SM);" -e "source data/functions.sql;" $(MYSQL_DB) > $@.tmp
	@mv $@.tmp $@
	@echo OK.

tmp/%.tbl: tests/%.tbl tmp/result.log
	@echo -n ...$*...
	@mysql $(MYSQL_ARGS) -e "select * from $*;" $(MYSQL_DB) > $@.tmp
	@diff -q $@.tmp $<
	@mv $@.tmp $@
	@echo OK.

.PHONY: old new clean all run
