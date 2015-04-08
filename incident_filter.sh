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
OUTPUT_REP=trace.html	# Default filename for the generated html report
FORCE_RESULTS=0

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


## HTML REPORT GENERATOR ######################################################

# Generate html view for catcher table
function gen_catcher_table {
	PRINT_VALUES=$1
	DB=$TEMP_DB
	TMPFILE=/var/tmp/incident_filter_tmp.$$;

	echo "generating catcher table..."

	echo "CATCHER:<br>" >> $OUTPUT_REP
	
	PRE='<td valign="bottom"><div class="rot"><nobr>&nbsp;&nbsp;&nbsp;'
	POS='</nobr></div></td>'

	echo 'select * from catcher;' | sqlite3 $DB > $TMPFILE

	echo "<table border=\"1\" cellspacing=\"0\" bgcolor=\"#C0C0C0\">" >> $OUTPUT_REP
	echo "<tr height=\"$MAX_TEXTLEN\">" >> $OUTPUT_REP

	echo $PRE "ID" $POS >> $OUTPUT_REP
	echo $PRE "MCC" $POS >> $OUTPUT_REP
	echo $PRE "MNC" $POS >> $OUTPUT_REP
	echo $PRE "LAC" $POS >> $OUTPUT_REP
	echo $PRE "CID" $POS >> $OUTPUT_REP
	echo $PRE "Timestamp" $POS >> $OUTPUT_REP
	echo $PRE "Duration" $POS >> $OUTPUT_REP
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
	echo $PRE "Longitude" $POS >> $OUTPUT_REP
	echo $PRE "Latitude" $POS >> $OUTPUT_REP
	echo $PRE "valid" $POS >> $OUTPUT_REP
	echo $PRE $SCORE $POS >> $OUTPUT_REP

	echo "</tr>" >> $OUTPUT_REP

	while read i; do

		echo "-Processing line: $i"

		echo "<tr bgcolor=\"#FFFFFF\">" >> $OUTPUT_REP
		ID=`echo $i | cut -d '|' -f 1`
		MCC=`echo $i | cut -d '|' -f 2`
		MNC=`echo $i | cut -d '|' -f 3`
		LAC=`echo $i | cut -d '|' -f 4`
		CID=`echo $i | cut -d '|' -f 5`
		TIMESTAMP=`echo $i | cut -d '|' -f 6`
		DURATION=`echo $i | cut -d '|' -f 7`

		echo "<td>$ID</td><td>$MCC</td><td>$MNC</td><td>$LAC</td><td>$CID</td><td>$TIMESTAMP</td><td>$DURATION</td>" >> $OUTPUT_REP
		
		for k in $(seq 8 24); do 

			MAX_SCORE_INDEX=`echo $k | awk '{printf "%i\n", $1-8}'`
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

		LONGITUDE=`echo $i | cut -d '|' -f 25`
		LATITUDE=`echo $i | cut -d '|' -f 26`
		VALID=`echo $i | cut -d '|' -f 27`
		SCORE=`echo $i | cut -d '|' -f 28`

		echo "<td>$LONGITUDE</td><td>$LATITUDE</td><td>$VALID</td><td>$SCORE</td>" >> $OUTPUT_REP

		echo "</tr>" >> $OUTPUT_REP
	done < $TMPFILE

	echo "</table>" >> $OUTPUT_REP
	rm $TMPFILE
}

# Generate html view for catcher table
function gen_events_table {
	DB=$TEMP_DB
	TMPFILE=/var/tmp/incident_filter_tmp.$$;

	echo "generating events table..."

	echo "EVENTS:<br>" >> $OUTPUT_REP
	
	PRE='<td valign="bottom"><div class="rot"><nobr>&nbsp;&nbsp;&nbsp;'
	POS='</nobr></div></td>'

	echo 'select * from events;' | sqlite3 $DB > $TMPFILE

	echo "<table border=\"1\" cellspacing=\"0\" bgcolor=\"#C0C0C0\">" >> $OUTPUT_REP
	echo "<tr height=\"150\">" >> $OUTPUT_REP

	echo $PRE "ID" $POS >> $OUTPUT_REP
	echo $PRE "Sequence" $POS >> $OUTPUT_REP
	echo $PRE "Timestamp" $POS >> $OUTPUT_REP
	echo $PRE "MCC" $POS >> $OUTPUT_REP
	echo $PRE "MNC" $POS >> $OUTPUT_REP
	echo $PRE "LAC" $POS >> $OUTPUT_REP
	echo $PRE "CID" $POS >> $OUTPUT_REP
	echo $PRE "Longitude" $POS >> $OUTPUT_REP
	echo $PRE "Latitude" $POS >> $OUTPUT_REP
	echo $PRE "valid" $POS >> $OUTPUT_REP
	echo $PRE "smsc" $POS >> $OUTPUT_REP
	echo $PRE "msisdn" $POS >> $OUTPUT_REP
	echo $PRE "event type" $POS >> $OUTPUT_REP
	echo "</tr>" >> $OUTPUT_REP

	while read i; do

		echo "-Processing line: $i"
		echo "<tr bgcolor=\"#FFFFFF\">" >> $OUTPUT_REP
		ID=`echo $i | cut -d '|' -f 1`
		SEQUENCE=`echo $i | cut -d '|' -f 2`
		TIMESTAMP=`echo $i | cut -d '|' -f 3`
		MCC=`echo $i | cut -d '|' -f 4`
		MNC=`echo $i | cut -d '|' -f 5`
		LAC=`echo $i | cut -d '|' -f 6`
		CID=`echo $i | cut -d '|' -f 7`
		LONGITUDE=`echo $i | cut -d '|' -f 8`
		LATITUDE=`echo $i | cut -d '|' -f 9`
		VALID=`echo $i | cut -d '|' -f 10`
		SMSC=`echo $i | cut -d '|' -f 11`
		MSISDN=`echo $i | cut -d '|' -f 12`
		EVENTTYPE=`echo $i | cut -d '|' -f 13`

		echo "<td>$ID</td><td>$SEQUENCE</td><td>$TIMESTAMP</td><td>$MCC</td><td>$MNC</td><td>$LAC</td><td>$CID</td><td>$LONGITUDE</td><td>$LATITUDE</td><td>$VALID</td><td>$SMSC</td><td>$MSISDN</td>" >> $OUTPUT_REP

		if [ $EVENTTYPE -eq 0 ]; then
			echo "<td>OTA/binary SMS</td>" >> $OUTPUT_REP
		elif [ $EVENTTYPE -eq 1 ]; then
			echo "<td>silent SMS</td>" >> $OUTPUT_REP
		elif [ $EVENTTYPE -eq 2 ]; then
			echo "<td>null paging</td>" >> $OUTPUT_REP
		else
			echo "<td>$EVENTTYPE</td>" >> $OUTPUT_REP		
		fi

		echo "</tr>" >> $OUTPUT_REP

	done < $TMPFILE

	echo "</table>" >> $OUTPUT_REP
	rm $TMPFILE
}

# Generate HTML report
function gen_report {
	TMPFILE=/var/tmp/incident_merge_tmp.$$;
	PRINT_VALUES=1

	echo "Generating HTML report:"
	echo "=============================================================================================="
	rm -f $OUTPUT_REP
	echo '<html><head><style type="text/css">.rot {transform: rotate(-90deg); width:2em;} </style></head><body>' >> $OUTPUT_REP

	gen_catcher_table $PRINT_VALUES
	echo "<br><br>" >> $OUTPUT_REP
	gen_events_table
	echo "<br><br><br><br>" >> $OUTPUT_REP
	echo "</body>" >> $OUTPUT_REP
	echo ""
}
###############################################################################


## FILTER AND ANALYZER ########################################################

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
	$GP_DIR/diag_import -g 127.0.0.1 $* > /dev/null
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

	cd $SS_PREBUILT_DIR
	sqlite3 $LOCALDIR/$TEMP_DB < ./event_analysis.sql 
	if [ $? -ne 0 ]; then
		echo "Error: Sqlite operation failed (event_analysis.sql), aborting..." >&2
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

	# Check if we got an app id and not an empty string
	if [ -z $INCIDENT ]; then
		echo "Error: App-Id missing, aborting..."
		exiterr
	fi

	# Check if the desired app-id folder exists 
	if ! [ -d $INPUT_DIR/$INCIDENT ]; then
		echo "Error: No such App-Id, aborting..."
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

		# Look into the catcher table to see if any catchers were detected
		CATCHER=`echo 'select * from catcher;' | sqlite3 ./$TEMP_DB`
		if [ $? -ne 0 ]; then
			echo "Error: Sqlite operation failed ('select * from catcher;' on temporary file trace.sqlite), aborting..." >&2
			exiterr
		fi

		# Look into the events table to see if any suspicious events (SMS, Paging) were detected
		EVENTS=`echo 'select * from events;' | sqlite3 ./$TEMP_DB`
		if [ $? -ne 0 ]; then
			echo "Error: Sqlite operation failed ('select * from events;' on temporary file trace.sqlite), aborting..." >&2
			exiterr
		fi

		# Perform further analysis and save results
		if [ -n "$CATCHER" ] || [ -n "$EVENTS" ] || [ $FORCE_RESULTS -eq 1 ]; then
			echo "==> ALARM: Incident detected, storing data..."

			# cp ./trace.log $INCIDENT.log # Log file is not needed, so we omit it
			cp ./$TEMP_DB $INCIDENT.sqlite

			create_db #Create a blank database
			create_pcap `ls -d1rt $INPUT_DIR/$INCIDENT/2__*_*_qdmon*-*-*-*UTC*`
			gen_report #Create html report

			cp ./trace.pcap $INCIDENT.pcap
			cp ./trace.results $INCIDENT.results
			cp ./$OUTPUT_REP $INCIDENT.html
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
	echo "usage: $0 -i input_dir -o output_dir [-a app_id] [-d dupavoid_db] [-D dupavoid_db] [-f]" >&2
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
	echo "   $0 -i ./incidents -o ./results"
	echo " * Analyze only new and memorize the ones that already got processed:"
	echo "   $0 -i ./incidents -o ./results -d foo.db"
	echo " * Creating a new duplicate avoidance database:"
	echo "   $0 -D workdone.db"
	echo " * Looking at a specific incident:"
	echo "   $0 -i ./incidents -a 1b561ccd"
	echo " * Looking at a specific incident, force to keep results:"
	echo "   $0 -i ./incidents -a 1b561ccd -f"
	echo ""
	exit 1
}

# Display banner
echo "SNOOPSNITCH INCIDENT FILTER UTILITY"
echo "==================================="

# Parse options
while getopts "hi:o:d:D:a:f" ARG; do
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
		f)
			FORCE_RESULTS=1
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

if ! [ -d "$OUTPUT_DIR" ]; then
	echo "Warning: Output directory does not exist, creating one..." >&2
	mkdir $OUTPUT_DIR
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
