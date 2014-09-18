MYSQL_ARGS = -u root --batch
MYSQL_DB   = test2g

old: SM = sm_2.4.sql
old: result.dat

new: SM = sm_2.4.new.sql
new: result.dat

clean:
	@rm -f result.dat result.dat.tmp

result.dat: main.sql data/functions.sql #data/expected.dat $(SM) 
	@mysql $(MYSQL_ARGS) -e "source $(SM);" -e "source data/functions.sql;" -e "source main.sql;" test2g > result.dat.tmp
	@diff -u result.dat.tmp data/expected.dat
	@mv result.dat.tmp result.dat

.PHONY: old new
