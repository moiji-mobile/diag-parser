#!/bin/bash

NEXT_SESSION=`echo "select max(id)+1 from session_info;" | mysql -uroot celldb -N`
NEXT_CELL=`echo "select max(id)+1 from cell_info;" | mysql -uroot celldb -N`

echo "Importing $1"
./diag_import $NEXT_SESSION $NEXT_CELL < $1
#gdb diag_import
