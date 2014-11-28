#!/bin/bash

NEXT_SESSION=`echo "select max(id)+1 from session_info;" | mysql -uroot celldb -N`
NEXT_CELL=`echo "select max(id)+1 from cell_info;" | mysql -uroot celldb -N`

#NEXT_SESSION=`echo "select if(max(id) is null, 16000000, max(id)+1) from session_info where id >= 16000000;" | mysql -uroot session_meta_test -pmoth*echo5Sigma -N`
#NEXT_CELL=`echo "select max(id)+1 from cell_info;" | mysql -uroot session_meta_test -pmoth*echo5Sigma -N`

echo "Importing $1"
./diag_import $NEXT_SESSION $NEXT_CELL $1
#gdb diag_import
