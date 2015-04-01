#!/bin/bash

# Incident merge script:
# This script takes the sqlite databases which were created with the incident filter
# utility and merges them into one results database.

INPUT_DIR=""		# Input directory where the .sqlite files can be found
OUTPUT_DB=""		# Output database
OP_EXIT_ON_ERROR=1	# 1=Stop immedeiately on error, 0=Ignore all errors

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
	echo "usage: $0 -i input_dir -d output_db [-D new_output_db]" >&2
	echo "Note: There are more parameters (static pathes) to" >&2
	echo "      set inside the the script file." >&2
	echo ""
	exit 1
}

# Display banner
echo "SNOOPSNITCH INCIDENT MERGER UTILITY"
echo "==================================="

# Parse options
while getopts "hi:o:d:D:a:" ARG; do
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
echo ""

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
echo "all done!"

