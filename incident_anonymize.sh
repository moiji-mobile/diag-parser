#!/bin/bash

# Incident anonymizer script:
# This script takes the sqlite databases which were created with the incident filter
# utility and strips possible private data from it

INPUT_DIR=""		# Input directory where the .sqlite files can be found
OP_EXIT_ON_ERROR=1	# 1=Stop immedeiately on error, 0=Ignore all errors
MG_DIR=/home/dexter/work/snoopsnitch/metagsm/ # Path to your metagsm installation

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
	echo "usage: $0 -i input_dir" >&2
	echo "Note: There are more parameters (static pathes) to" >&2
	echo "      set inside the the script file." >&2
	echo ""
	echo "Description:"
	echo " * This tool walks through the filtered incident database files and"
	echo "   creates an anonymized copy."
	echo ""
	echo "Examples:"
	echo " * Perform anonymization:"
	echo "   $0 -i ../inputfiles/"
	echo ""
	exit 1
}

# Display banner
echo "SNOOPSNITCH INCIDENT ANONYMIZER UTILITY"
echo "======================================="

# Parse options
OUTPUT_REP_NUMBERS=0
while getopts "hi:" ARG; do
	case $ARG in
		h)
			usage
			;;
		i)
			INPUT_DIR=$OPTARG
			;;
	esac
done

# Check if valid input and output directorys are set
if [ -z "$INPUT_DIR" ]; then
	echo "Error: No input folder supplied, aborting..." >&2
	usage
fi

INPUT_DIR=`realpath $INPUT_DIR`
echo "Input directory: $INPUT_DIR"
echo ""

# Clear results from previous run
LOCALDIR=$PWD
cd $INPUT_DIR
rm -f *.anon.sqlite
cd $LOCALDIR

# Merge
echo "Anonymizing incidents:"
echo "=============================================================================================="
for DATABASE in $(ls $INPUT_DIR/*.sqlite)
do
	# Derive app_id from the filename
	DIRNAME=`dirname $DATABASE`
	INCIDENT=`basename ${DATABASE%.*}`
	DATABASE_ANONYMIZED=$DIRNAME/$INCIDENT.anon.sqlite

	# Anonymize databases
	echo "Anonymizing: $INCIDENT"
	cp $DATABASE $DATABASE_ANONYMIZED

	sqlite3 $DATABASE_ANONYMIZED < $MG_DIR/anonymize.sql
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (anonymize.sql), aborting..." >&2
		exiterr
	fi
done
echo ""

echo "all done!"

