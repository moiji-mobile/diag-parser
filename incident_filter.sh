#!/bin/bash

# Incident filter script:
# This scripts analyzes and filters incidents from the traces input directory
# All traces that match the incident criteria (at least 1 entry in the cater
# table) will be stored in the outut directory. 

# Options (please set up before use)
INPUT_DIR="" 		# Default input path
OUTPUT_DIR=""		# Default output path
SS_DIR=/home/dexter/snoopsnitch # Path to your snoopsnitch installation
OP_EXIT_ON_ERROR=1	# 1=Stop immedeiately on error, 0=Ignore all errors
OP_STOPWATCH=0		# 1=Monitor processing times, 0=Do not monitor times
DUPAVOID_DB=""		# Default path to your duplicate work avoidance db

# Absolute pathes to the snoopsnitch installation (please do not change)
SS_PREBUILT_DIR=$SS_DIR/analysis/prebuilt
SS_CATCHER_DIR=$SS_DIR/analysis/catcher
SS_ASSET_DIR=$SS_DIR/SnoopSnitch/assets
GP_DIR=$SS_DIR/contrib/gsm-parser

# Relative pathes (please do not change)
WORKING_DIR=$PWD	# Don't change unless you have a good reason
TEMP_DB=metadata.db	# Don't change unless you change it in gsm-parser too

## STOPWATCH ##################################################################

# Reset the stopwatch
function stopwatch_start {
	if [ $OP_STOPWATCH -eq 1 ]; then
		STARTTIME=$(date +%s)
	fi
}

# Stop and read the stopwatch
function stopwatch_stop {
	if [ $OP_STOPWATCH -eq 1 ]; then
		ELAPSEDTIME=$[$(date +%s)-$STARTTIME]
		echo "Info: Operation took $ELAPSEDTIME second(s)"
	fi
}

###############################################################################


## DUPLICATE WORK AVOIDANCE ###################################################

# Note: When the path to the database ($DUPAVOID_DB) is set to an empty
#       string, then the dupavoid-feature is disabled.

# Create a new database to store the info for the work thats already done
function dupavoid_create_db {
	echo "Creating a new duplicate work avoidance database at: $DUPAVOID_DB"
	rm -f $DUPAVOID_DB
	echo 'CREATE TABLE work(appid varchar(255) not null unique, filecount int);' | sqlite3 $DUPAVOID_DB
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (create table), aborting..." >&2
		exiterr
	fi
	exit
}

# Update duplicate work avoidance database, first parameter is the app-id,
# second is the filecount. If no database is set, the function does nothing
function dupavoid_update_db {
	if ! [ -z $DUPAVOID_DB ]; then
		APPID_TO_UPDATE=$1
		FILECOUNT_TO_UPDATE=$2	
		SQLITE_OPERATION='replace into work (appid, filecount) values ("'$APPID_TO_UPDATE'",'$FILECOUNT_TO_UPDATE');'
		echo $SQLITE_OPERATION | sqlite3 $DUPAVOID_DB
		if [ $? -ne 0 ]; then
			echo "Error: Sqlite operation failed (replace into work), aborting..." >&2
			exiterr
		fi
	fi
}

# Check the duplicate work avoidance database if there is work to do, first 
# parameter is the app-id, second is the filecount. If no database is set,
# the function does nothing. When the function returns 1, the incident has
# never been analyzed before, has new data or the duplicate work avoidance
# feature has been disabled.
function dupavoid_checkwork {
	if ! [ -z $DUPAVOID_DB ]; then
		APPID_TO_UPDATE=$1
		FILECOUNT_TO_UPDATE=$2


		QUERY_RESULT=`echo "select * from work where appid = \"$APPID_TO_UPDATE\" and filecount = $FILECOUNT_TO_UPDATE;" | sqlite3 $DUPAVOID_DB`
		if [ $? -ne 0 ]; then
			echo "Error: Sqlite operation failed (replace into work), aborting..." >&2
			exiterr
		fi

		if [ -z $QUERY_RESULT ]; then
			return 1
		else 
			return 0
		fi
	fi

	return 1
}
###############################################################################


## FILTER #####################################################################

# Exit on error
function exiterr {
	if [ $OP_EXIT_ON_ERROR -eq 1 ]; then
		exit 1
	else
		echo "Warning: Ignoring error..."
	fi
}

# Cleanup all temporary files
function cleanup {
	cd $WORKING_DIR
	if [ $? -ne 0 ]; then
		echo "Error: Wrong directory, aborting..." >&2
		exiterr
	fi
	cd $OUTPUT_DIR
	if [ $? -ne 0 ]; then
		echo "Error: Wrong directory, aborting..." >&2
		exiterr
	fi
	echo "cleaning up..."
	rm -f ./trace.*
	rm -f ./$TEMP_DB
}

# Create a new database from the prebuilt sql files
function create_db {
	stopwatch_start
	LOCALDIR=$PWD;
	echo "creating database..."
	cd $GP_DIR

	sqlite3 $LOCALDIR/$TEMP_DB < ./cell_info.sql
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (cell_info.sql), aborting..." >&2
		exiterr
	fi

	sqlite3 $LOCALDIR/$TEMP_DB < ./si.sql
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (si.sql), aborting..." >&2
		exiterr
	fi

	sqlite3 $LOCALDIR/$TEMP_DB < ./sms.sql
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (sms.sql), aborting..." >&2
		exiterr
	fi

	cd $LOCALDIR
	stopwatch_stop
}

# Create a TCPDUMP from the trace files
function create_pcap {
	stopwatch_start
	echo "creating pcap..."
	dumpcap -q -i lo -w trace.pcap -f "udp port 4729" &
	DUMPCAP_PID=$!
	sleep 1
	diag_import -g 127.0.0.1 $* > /dev/null
	sleep 1
	sync
	kill -TERM ${DUMPCAP_PID}
	stopwatch_stop
}

# Process the input files with diag_inport
function process_files {
	stopwatch_start
	echo "Processing input files..."
	ls -d1rt $INPUT_DIR/$INCIDENT/2__*_*_qdmon*-*-*-*UTC*
	NUMBER_OF_PROCESSED_FILES=`ls -d1rt $INPUT_DIR/$INCIDENT/2__*_*_qdmon*-*-*-*UTC* | wc -l`

	$GP_DIR/diag_import `ls -d1rt $INPUT_DIR/$INCIDENT/2__*_*_qdmon*-*-*-*UTC*` > trace.log
	if [ $? -ne 0 ]; then
		echo "Error: Reading trace data into database failed (diag_import), aborting..." >&2
		exiterr
	fi
	echo "info: Number of files processed: $NUMBER_OF_PROCESSED_FILES"
	stopwatch_stop

	return $NUMBER_OF_PROCESSED_FILES
}

# Perform analysis operations on the database
function perform_analysis {
	stopwatch_start
	echo "Analysing..."
	sqlite3 ./$TEMP_DB < $SS_ASSET_DIR/local.sqlx 
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (local.sqlx), aborting..." >&2
		exiterr
	fi

	LOCALDIR=$PWD;

	cd $SS_PREBUILT_DIR
	sqlite3 $LOCALDIR/$TEMP_DB < ./config.sql 
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (config.sql), aborting..." >&2
		exiterr
	fi
	cd $LOCALDIR

	cd $SS_PREBUILT_DIR
	sqlite3 $LOCALDIR/$TEMP_DB < ./location.sql 
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (location.sql), aborting..." >&2
		exiterr
	fi
	cd $LOCALDIR

	cd $SS_CATCHER_DIR
	sqlite3 $LOCALDIR/$TEMP_DB < ./validate.sql | tee $LOCALDIR/trace.results
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (validate.sql), aborting..." >&2
		exiterr
	fi
	cd $LOCALDIR
	stopwatch_stop
}

# Perform inicident analysis
function analyze {
	INCIDENT=$1

	echo "Analyzing incident: $INCIDENT"
	echo "=============================================================================================="

	if [ -z $INCIDENT ]; then
		echo "Error: App-Id missing, aborting..."
		exiterr
	fi

	# Check if there is work to do
	NUMBER_OF_TO_PROCESS=`ls -d1rt $INPUT_DIR/$INCIDENT/2__*_*_qdmon*-*-*-*UTC* | wc -l`
	dupavoid_checkwork $INCIDENT $NUMBER_OF_TO_PROCESS

	if [ $? -ne 0 ]; then

		# Change back into working directory
		cd $WORKING_DIR
		if [ $? -ne 0 ]; then
			echo "Error: Wrong directory, aborting..." >&2
			exiterr
		fi

		# Create output directory if it does not already exist
		if ! [ -d $OUTPUT_DIR ]; then
			mkdir $OUTPUT_DIR
		fi	

		# Go to the output directory
		cd $OUTPUT_DIR
		if [ $? -ne 0 ]; then
			echo "Error: Wrong directory, aborting..." >&2
			exiterr
		fi

		# Check if the incident has already been analyzed, if so, just do the analysis again
		if [ -e $INCIDENT.log ]; then
			echo "Warning: The current incident has been analyzed before, results will be overwritten!"
		fi

		# Create a fresh database
		cleanup
		create_db

		# Process input files
		process_files
		NUMBER_OF_PROCESSED_FILES=$?

		# Apply extended analysis (Sqlite operations)
		perform_analysis

		# Look into the cater table to see if any catchers were detected, if so, store
		# all data into the output dir
		CATCHER=`echo 'select * from catcher;' | sqlite3 ./$TEMP_DB`
		if [ $? -ne 0 ]; then
			echo "Error: Sqlite operation failed ('select * from catcher;' on temporary file trace.sqlite), aborting..." >&2
			exiterr
		fi

		if [ -n "$CATCHER" ]; then
			echo "==> ALARM: Incident detected, storing data..."
			# Rename files
			# cp ./trace.log $INCIDENT.log # Log file is not needed, so we omit it
			cp ./$TEMP_DB $INCIDENT.sqlite

			create_db #Create a blank database
			create_pcap `ls -d1rt $INPUT_DIR/$INCIDENT/2__*_*_qdmon*-*-*-*UTC*`
			cp ./trace.pcap $INCIDENT.pcap
			cp ./trace.results $INCIDENT.results
		else
			echo "==> Trace does not match the incident criteria, ignoring..."
		fi

		cd $WORKING_DIR
		if [ $? -ne 0 ]; then
			echo "Error: Wrong directory, aborting..." >&2
			exiterr
		fi
		cleanup

		# Update duplicate work avoidance database
		dupavoid_update_db $INCIDENT $NUMBER_OF_PROCESSED_FILES 
	else
		echo "Info: This incident has been analyzed before and no new uploads were"
		echo "      detected. Because of this, the incident will be excluded from"
		echo "      any further analysis until new uploads are detected."
	fi

	echo ""
}
###############################################################################


## MAIN PROGRAM ###############################################################

# Display usage (help) information and exit
function usage {
	echo "usage: $0 -i input_dir -o output_dir [-a app_id] [-d dupavoid_db] [-D dupavoid_db]" >&2
	echo "Note: There are more parameters (static pathes) to" >&2
	echo "      set inside the the script file." >&2
	echo ""
	echo "Description:"
	echo " * This tool walks through a folder with incidents (app IDs) and"
	echo "   performs a basic analysis that can tell if the incident has been"
	echo "   caused by an imsi-catcher. For all incidents that match the"
	echo "   analysis results are stored either in the local directory or in"
	echo "   the output directory the user specified"
	echo " * In order to avoid duplicate work, the tool can memorize already"
	echo "   processed incidents in a database. The incident is then excluded"
	echo "   from the processing until the user uploads more data."
	echo ""
	echo "Examples:"
	echo " * Analyze all incidents:"
	echo "   $0 -i ./incidents"
	echo " * Analyze only new and memorize the ones that already got processed:"
	echo "   $0 -i ./incidents -d foo.db"
	echo " * Creating a new duplicate avoidance database:"
	echo "   $0 -D workdone.db"
	echo " * Looking at a specific incident:"
	echo "   $0 -i ./incidents -a 1b561ccd"
	echo ""
	exit 1
}

# Display banner
echo "SNOOPSNITCH INCIDENT FILTER UTILITY"
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
		o)
			OUTPUT_DIR=$OPTARG
			;;
		a)
			APP_ID=$OPTARG
			;;
		d)
			DUPAVOID_DB=$OPTARG
			;;
		D)
			DUPAVOID_DB=$OPTARG
			dupavoid_create_db # Creates a new db and then exists
			;;

	esac
done

# Check if valid input and output directorys are set
if [ -z "$INPUT_DIR" ]; then
	echo "Error: No input folder supplied, aborting..." >&2
	usage
fi

if ! [ -d $INPUT_DIR ]; then
	echo "Error: Specified input directory does not exist..." >&2
	exit 1
fi	

if [ -z "$OUTPUT_DIR" ]; then
	echo "Warning: No output folder supplied, results will be written to local directory..." >&2
	OUTPUT_DIR=./
fi

INPUT_DIR=`realpath $INPUT_DIR`
OUTPUT_DIR=`realpath $OUTPUT_DIR`

echo "Input directory: $INPUT_DIR"
echo "Output directory: $OUTPUT_DIR"
if ! [ -z $DUPAVOID_DB ]; then

	if [ -e $DUPAVOID_DB ]; then
		DUPAVOID_DB=`realpath $DUPAVOID_DB`
		echo "Database for dublicate work avoidance: $DUPAVOID_DB"
	else
		echo "Error: Could not read duplicate work avoidance database, exiting..."
		exiterr
	fi
fi
echo ""


# Walk through all files in the incident directory and perform filter operations,
# the results will be written to the OUTPUT_DIR.
if [ -z $APP_ID ]; then
	for INCIDENT in $(ls $INPUT_DIR)
	do
		analyze $INCIDENT
	done
else
	# Make sure the duplication avoidance feature is disabled,
	# because in the dedicated app-id case we do not want the
	# system to prevent the analysis, nor do we want to prevent
	# future automated analysis.
	DUPAVOID_DB="" 

	analyze $APP_ID
fi

echo "all done!"

###############################################################################
