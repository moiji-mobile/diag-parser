#!/bin/bash

# Incident merge script:
# This script takes the sqlite databases which were created with the incident filter
# utility and merges them into one results database.

INPUT_DIR=""		# Input directory where the .sqlite files can be found
OUTPUT_DB=""		# Output database filename
OUTPUT_REP=""		# HTML-Report filename
OP_EXIT_ON_ERROR=1	# 1=Stop immedeiately on error, 0=Ignore all errors

# Fine tuning for the expected score range for each column
SCORE_COLUMN_MAX[0]=1	# a1
SCORE_COLUMN_MAX[1]=1	# a2
SCORE_COLUMN_MAX[2]=1	# a4
SCORE_COLUMN_MAX[3]=1	# a5
SCORE_COLUMN_MAX[4]=1	# k1
SCORE_COLUMN_MAX[5]=1	# k2
SCORE_COLUMN_MAX[6]=1	# c1
SCORE_COLUMN_MAX[7]=1	# c2
SCORE_COLUMN_MAX[8]=0.57 # c3
SCORE_COLUMN_MAX[9]=6	# c4
SCORE_COLUMN_MAX[10]=2	# c5
SCORE_COLUMN_MAX[11]=1.5 # t1
SCORE_COLUMN_MAX[12]=1	# t3
SCORE_COLUMN_MAX[13]=1	# t4
SCORE_COLUMN_MAX[14]=1	# r1
SCORE_COLUMN_MAX[15]=1	# r2
SCORE_COLUMN_MAX[16]=1	# f1
SCORE_COLUMN_MAX[17]=8	# score

# Full text description for each score
MAX_TEXTLEN=450
A1='[A1] Different LAC/CID for the same ARFCN'
A2='[A2] Inconsistent LAC'
A3='[A3] Only 2G available'
A4='[A4] Same LAC/CID on different ARFCNs'
A5='[A5] Single LAC occurrence'
K1='[K1] No neighboring cells'
K2='[K2] High cell reselect offset'
C1='[C1] Encryption Downgrade'
C2='[C2] Delayed CIPHER MODE COMPLETE ack.'
C3='[C3] CIPHER MODE CMD msg. without IMEISV'
C4='[C4] ID requests during location update'
C5='[C5] Cipher setting out of average'
T1='[T1] Low registration timer'
T3='[T3] Paging without transaction'
T4='[T4] Orphaned traffic channel'
T7='[T7] MS sends on high power'
R1='[R1] Inconsistent neighbor list'
R2='[R2] High number of paging groups'
F1='[F1] Few paging requests'
SCORE='final score'


## DATABASE HANDLING ##########################################################

# Table that will accumulate the event results
read -d '' TABLE_EVENTS <<"EOF"
CREATE TABLE main.events
(
	appid char(8) NOT NULL,
	id integer,
	mcc integer,
	mnc integer,
	lac integer,
	cid integer,
	timestamp datetime,
	duration int,
	a1 FLOAT,
	a2 FLOAT,
	a4 FLOAT,
	a5 FLOAT,
	k1 FLOAT,
	k2 FLOAT,
	c1 FLOAT,
	c2 FLOAT,
	c3 FLOAT,
	c4 FLOAT,
	c5 FLOAT,
	t1 FLOAT,
	t3 FLOAT,
	t4 FLOAT,
	r1 FLOAT,
	r2 FLOAT,
	f1 FLOAT,
	longitude DOUBLE NOT NULL,
	latitude DOUBLE NOT NULL,
	valid SMALLINT,
	score FLOAT
);
EOF

# Create a new database to store the output data
function create_db {
	echo "Creating a new results database at: $OUTPUT_DB"
	rm -f $OUTPUT_DB
	echo $TABLE_EVENTS | sqlite3 $OUTPUT_DB
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (create table), aborting..." >&2
		exiterr
	fi
	exit
}
###############################################################################


## REPORT GENERATION ##########################################################

# Generate HTML table
function gen_table {
	QUERY=$1
	PRINT_VALUES=$2
	DB=$OUTPUT_DB
	TMPFILE=/var/tmp/incident_merge_tmp.$$;

	PRE='<td valign="bottom"><div class="rot"><nobr>&nbsp;&nbsp;&nbsp;'
	POS='</nobr></div></td>'

	echo $QUERY | sqlite3 $DB > $TMPFILE

	echo "<table border=\"1\" cellspacing=\"0\" bgcolor=\"#C0C0C0\">" >> $OUTPUT_REP
	echo "<tr height=\"$MAX_TEXTLEN\">" >> $OUTPUT_REP

	# Table column descriptions: begin
	echo $PRE MCC $POS >> $OUTPUT_REP
	echo $PRE MNC $POS >> $OUTPUT_REP
	echo $PRE $A1 $POS >> $OUTPUT_REP
	echo $PRE $A2 $POS >> $OUTPUT_REP
	echo $PRE $A4 $POS >> $OUTPUT_REP
	echo $PRE $A5 $POS >> $OUTPUT_REP
	echo $PRE $K1 $POS >> $OUTPUT_REP
	echo $PRE $K2 $POS >> $OUTPUT_REP
	echo $PRE $C1 $POS >> $OUTPUT_REP
	echo $PRE $C2 $POS >> $OUTPUT_REP
	echo $PRE $C3 $POS >> $OUTPUT_REP
	echo $PRE $C4 $POS >> $OUTPUT_REP
	echo $PRE $C5 $POS >> $OUTPUT_REP
	echo $PRE $T1 $POS >> $OUTPUT_REP
	echo $PRE $T3 $POS >> $OUTPUT_REP
	echo $PRE $T4 $POS >> $OUTPUT_REP
	echo $PRE $R1 $POS >> $OUTPUT_REP
	echo $PRE $R2 $POS >> $OUTPUT_REP
	echo $PRE $F1 $POS >> $OUTPUT_REP
	echo $PRE $SCORE $POS >> $OUTPUT_REP
	# Table column descriptions: end

	echo "</tr>" >> $OUTPUT_REP

	for i in $(cat $TMPFILE); do

		echo "<tr>" >> $OUTPUT_REP
		MCC=`echo $i | cut -d '|' -f 1`
		MNC=`echo $i | cut -d '|' -f 2`

		echo "<td>$MCC</td><td>$MNC</td>"  >> $OUTPUT_REP

		echo "-Processing operator: $MCC, $MNC"

		for k in $(seq 3 20); do 

			MAX_SCORE_INDEX=`echo $k | awk '{printf "%i\n", $1-3}'`
			MAX_SCORE=${SCORE_COLUMN_MAX[$MAX_SCORE_INDEX]}

			#Compute rounded values and the color value
			VALUE=`echo $i | cut -d '|' -f $k`
			COLORVALUE=`echo $VALUE $MAX_SCORE | awk '{printf "%i\n", $1*255/$2}'`

			#Detect when one of the score values exceeds its valid range
			CLIPPED=0
			if [ $COLORVALUE -gt 255 ]; then
				CLIPPED=1
			fi
			if [ $COLORVALUE -lt 0 ]; then
				CLIPPED=2
			fi

			# Draw table row
			if [ $CLIPPED -eq 0 ]; then
				COLOR=`echo $COLORVALUE | awk '{printf "#%02x%02x%02x\n", 255-$1, 255-$1, 255-$1}'`
			elif [ $CLIPPED -eq 1 ]; then
				COLOR=`echo $COLORVALUE | awk '{printf "#%02x%02x%02x\n", 255, 0, 0}'`	
			else
				COLOR=`echo $COLORVALUE | awk '{printf "#%02x%02x%02x\n", 0, 0, 255}'`	
			fi

			echo "<td bgcolor=\"$COLOR\">" >> $OUTPUT_REP

			if [ $COLORVALUE -gt 150 ]; then
				echo "<font color=\"white\">" >> $OUTPUT_REP
			elif [ $COLORVALUE -eq 0 ]; then
				echo "<font color=\"grey\">" >> $OUTPUT_REP
			else
				echo "<font color=\"black\">" >> $OUTPUT_REP
			fi

			if [ $PRINT_VALUES -eq 1 ]; then
				echo $VALUE | awk '{printf "%.2f\n", $1}' >> $OUTPUT_REP
			else
				echo '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;' >> $OUTPUT_REP
			fi

			echo "</font>" >> $OUTPUT_REP
			echo "</td>" >> $OUTPUT_REP
		done
		echo "</tr>" >> $OUTPUT_REP
	done;

	echo "</table>" >> $OUTPUT_REP
	rm $TMPFILE
}

# Generate HTML-Report
function gen_report {
	DB=$OUTPUT_DB
	PRINT_VALUES=$1

	echo "Generating HTML report:"
	echo "=============================================================================================="
	rm -f $OUTPUT_REP

	AVG_QUERY="select mcc, mnc, avg(a1), avg(a2), avg(a4), avg(a5), avg(k1), avg(k2), avg(c1), avg(c2), avg(c3), avg(c4), avg(c5), avg(t1), avg(t3), avg(t4), avg(r1), avg(r2), avg(f1), avg(score) from events group by mcc,mnc;" 
	MAX_QUERY="select mcc, mnc, max(a1), max(a2), max(a4), max(a5), max(k1), max(k2), max(c1), max(c2), max(c3), max(c4), max(c5), max(t1), max(t3), max(t4), max(r1), max(r2), max(f1), max(score) from events group by mcc,mnc;" 

	echo '<html><head><style type="text/css">.rot {transform: rotate(-90deg); width:2em;} </style></head><body>' >> $OUTPUT_REP

	echo "Average..."
	echo "Average over all scores per MCC/MNC<br>" >> $OUTPUT_REP
	gen_table "$AVG_QUERY" $PRINT_VALUES

	echo "<br><br><br><br>" >> $OUTPUT_REP

	echo "Maximum..."
	echo "Maximum over all scores per MCC/MNC<br>" >> $OUTPUT_REP
	gen_table "$MAX_QUERY" $PRINT_VALUES

	echo "</body>" >> $OUTPUT_REP

	echo ""
}
###############################################################################


## MAIN PROGRAM ###############################################################

# Exit on error
function exiterr {
	if [ $OP_EXIT_ON_ERROR -eq 1 ]; then
		exit 1
	else
		echo "Warning: Ignoring error..."
	fi
}

# Display usage (help) information and exit
function usage {
	echo "usage: $0 -i input_dir -d output_db [-D new_output_db] [-r html_report -n ]" >&2
	echo "Note: There are more parameters (static pathes) to" >&2
	echo "      set inside the the script file." >&2
	echo "Note: Option -n adds numeric values to the report display"
	echo ""
	echo "Description:"
	echo " * This tool walks through the filtered incident database files and"
	echo "   merges each of it into one large database. After the merging"
	echo "   the collected results are analyzed and presented as an HTML file"
	echo ""
	echo "Examples:"
	echo " * Create a new database:"
	echo "   $0 -D /path/to/my/db.sqlite"
	echo " * Perform analysis:"
	echo "   $0 -i ../inputfiles/ -d /path/to/my/db.sqlite -r ./report.html"
	echo "   $0 -i ../inputfiles/ -d /path/to/my/db.sqlite -r ./report.html -n"
	echo ""
	exit 1
}

# Display banner
echo "SNOOPSNITCH INCIDENT MERGER UTILITY"
echo "==================================="

# Parse options
OUTPUT_REP_NUMBERS=0
while getopts "hi:o:d:D:a:r:n" ARG; do
	case $ARG in
		h)
			usage
			;;
		i)
			INPUT_DIR=$OPTARG
			;;
		d)
			OUTPUT_DB=$OPTARG
			;;
		D)
			OUTPUT_DB=$OPTARG
			create_db # Creates a new db and then exists
			;;
		r)
			OUTPUT_REP=$OPTARG
			;;
		n)
			OUTPUT_REP_NUMBERS=1
			;;
	esac
done

# Check if valid input and output directorys are set
if [ -z "$INPUT_DIR" ]; then
	echo "Error: No input folder supplied, aborting..." >&2
	usage
fi

if ! [ -e $OUTPUT_DB ]; then
	echo "Error: No output database supplied, aborting..." >&2
	exit 1
fi	


INPUT_DIR=`realpath $INPUT_DIR`
OUTPUT_DB=`realpath $OUTPUT_DB`
echo "Input directory: $INPUT_DIR"
echo "Output database: $OUTPUT_DB"
if ! [ -z $OUTPUT_REP ]; then
	touch $OUTPUT_REP
	OUTPUT_REP=`realpath $OUTPUT_REP`
	echo "HTML report: $OUTPUT_REP"
fi
echo ""

# Merge
echo "Merging incidents:"
echo "=============================================================================================="
for DATABASE in $(ls $INPUT_DIR/*.sqlite)
do
	# Derive app_id from the filename
	FILENAME=`basename $DATABASE`
	INCIDENT=${FILENAME%.*}

	# Merge catcher data
	echo "Merging: $DATABASE"
	echo 'attach '\"$DATABASE\"' as incident; insert into main.events select '\"$INCIDENT\"', * from incident.catcher; detach incident;' | sqlite3 $OUTPUT_DB
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (merging), aborting..." >&2
		exiterr
	fi
done
echo ""

# Optional: Generate HTML-Report
if ! [ -z $OUTPUT_REP ]; then
	gen_report $OUTPUT_REP_NUMBERS
fi


echo "all done!"

