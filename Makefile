MYSQL_ARGS = -u root --batch
MYSQL_DB   = test2g

all: new

old: SM = sm_2.4.sql
old: run

new: SM = sm_2.4.new.sql
new: run

clean:
	@rm -f result.dat result.dat.tmp

run: main.sql data/functions.sql data/expected.dat $(SM) 
	@mysql $(MYSQL_ARGS) -e "source $(SM);" -e "source data/functions.sql;" -e "source main.sql;" test2g > result.dat.tmp
	@diff -u result.dat.tmp data/expected.dat
	@mv result.dat.tmp result.dat
	@echo OK.

.PHONY: old new clean all run
