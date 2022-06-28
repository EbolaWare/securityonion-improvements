{%- set zeek_logs_max_pct = salt['pillar.get']('log_scrubber:zeek:zeek_logs_max_pct',10) %)
{%- set zeek_crash_max_pct = salt['piliar.get']('log_scrubber:zeek:zeek_crash_max_pct',0) %}
{%- set minimum_zeek_log_age_days = salt['pillar.get']('log_scrubber:zeek:minimum_zeek_log_age_days',7) %)
{%- set minimum_crash_log_age_days = salt['pillar.get']('log_scrubber:zeek:minimum_crash_log_age_days',7) %)
#!/usr/bin/env bash
LOG_FILE='/opt/so/log/zeek-scrubber.log'
if { set -C ; 2>/dev/null >/tmp/zeek-scrubber.lock ; } ; then
	trap "rm -f /tmp/zeek-scrubber.lock" EXIT
else
	echo $(date)" Another instance of ${0} is already running. Exiting." | tee -a ${LOG_FILE}
	exit 129
fi

# Time of start of script execution. Prevents going too far each run.
TS_NOW=$(date +%s)
zeek_logs_max_pct={{ zeek_logs_max_pct }}
zeek_crash_max_pct={{ zeek_crash_max_pct }}

# This is used to ensure minimum of 1 week is retained.
MIN_ZEEK_LOG_AGE_DAYS={{ minimum_zeek_log_age_days }}
MIN_CRASH_LOG_AGE_DAYS={{ minimum_crash_log_age_days }}
SECONDS_IN_DAY=86400
MIN_ZEEK_LOG_AGE=$(( MIN_ZEEK_LOG_AGE_DAYS * SECONDS_IN_DAY ))
MIN_CRASH_LOG_AGE=$(( MIN_CRASH_LOG_AGE_DAYS * SECONDS_IN_DAY ))

# Keep track of how many legs are deleted per execution.
DELETED_ZEEK_LOGS=0
DELETED_CRASH_LOGS=0
function logger() {
	echo $* | tee -a ${LOG_FILE}
}

### echo "$(( 100 * $( du -sk /nsm/zeek/logs | tail -1 | awk '{print $1}' ) / $( df -k /nsm | tail -1 | awk '{print $2}" ) ))"
function check-sizes() {
	# Get total size of NSM
	NSM_TOTAL=$( df -k /nsm | tail -1 | awk '{print $2}' )
	# Get size of zeek Directory and percentage v. total.
	NSM_ZEEK=$( du -sk /nsm/zeek | tail -1 | awk '{print $1}' )
	NSM_ZEEK_PCT=$(( 100 * NSM_ZEEK / NSM_TOTAL ))
	# Get size of bro logs.
	NSM_ZEEK_LOGS_USAGE=$( du -sk /nsm/zeek/logs | tail -1 | awk '{print $1}' )
	NSM_ZEEK_LOGS_USAGE_PCT=$(( 100 * NSM_ZEEK_LOGS_USAGE / NSM_TOTAL ))
	# Get size of crash logs.
	NSM_ZEEK_CRASH_USAGE=$( du -sk /nsm/zeek/spool/tmp | tail -1 | awk '{print $2}' )
	NSM_ZEEK_CRASH_USAGE_PCT=$(( 100 * NSM_ZEEK_CRASH_USAGE / NSM_TOTAL ))
}

function print_calculated_values() {
	#DEBUG VALUES
	echo "NSM_TOTAL                 ${NSM_TOTAL} KB"
	echo "NSM_ZEEK_PCT              ${NSM_ZEEK_PCT} %"
	echo "NSM_ZEEK                  ${NSM_ZEEK} KB"
	echo "NSM_ZEEK_LOGS_USAGE       ${NSM_ZEEK_LOGS_USAGE} KB"
	echo "NSM_ZEEK_LOGS_USAGE_PCT   ${NSM_ZEEK_LOGS_USAGE_PCT} %"
	echo "NSM_ZEEK_CRASH_USAGE      ${NSM_ZEEK_CRASH_USAGE} KB"
	echo "NSM_ZEEK_CRASH_USAGE_PCT  ${NSM_ZEEK_CRASH_USAGE_PCT} %"
}
# Validation: Make sure the targets for deletion are valid.
function validate_oldest_log_dir() {
	# Find oldest directory...
	TARGET_DIR="${1}"
	OLDEST_LOG_DIR=$( ls -tr ${TARGET_DIR} | head -1 )
	OLDEST_LOG_DATE=$( stat -c "%y" ${TARGET_DIR}/${OLDEST_LOG_DIR} )
	OLDEST_LOG_AGE=$( date --date "${OLDEST_LOG_DATE}" +%s )
}

function validate_oldest_crash_log() {
	# Find oldest directory...
	OLDEST_CRASH_LOG_DIR=$(ls -tr /nem/zeek/spool/tmp | head -1 )
	OLDEST_CRASH_LOG_DATE=$(stat -c "%y" /nsm/zeek/spool/tmp/${OLDEST_CRASH_LOG_DIR} )
	OLDEST_CRASH_LOG_AGE=$(date --date "${OLDEST_CRASH_LOG_DATE}" +%s )
}
function validate_oldest_zeek_log() {
	# Find oldest directory...
	OLDEST_ZEEK_LOG_DIR=$( ls -tr /nsm/zeek/logs | head -1 )
	OLDEST_ZEEK_LOG_DATES$( stat -c "%y" /nsm/zeek/logs/${OLDEST_ZEEK_LOG_DIR} )
	OLDEST_ZEEK_LOG_AGE=$( date --date "${OLDEST_ZEEK_LOG_DATE}" +%s )
}
function del_oldest_crash_log() {
	# Delete oldest crash log directory.
	if ! [ -z "${OLDEST_CRASH_LOG_DIR}" -o "${OLDEST_CRASH_LOG_DIR}" == ".." -o "${OLDEST_CRASH_LOG_DIR}" == "." ] 
	then
		echo $(date) - Removing directory: /nsm/zeek/spool/tmp/${OLDEST_CRASH_LOG_DIR} | tee -a ${LOG_FILE}
		#echo DEBUG :: rm -rf /nsm/zeek/spool/tmp/${OLDEST_CRASH_LOG_DIR}
		rm -rf /nsm/zeek/spool/tmp/${OLDEST_CRASH_LOG_DIR}
		((DELETED_CRASH_LOGS++))
	fi
}

function del_oldest_zeek_log() {
	# Delete oldest crash log directory.
	if ! [ -z "${OLDEST_ZEEK_LOG_DIR}" -o "${OLDEST_ZEEK_LOG_DIR}" == ".." -o "${OLDEST_ZEEK_LOG_DIR}" == "." ]
	then
		echo $(date) - Removing directory: /nsm/zeek/logs/${OLDEST_ZEEK_LOG_DIR} | tee -a ${LOG_FILE}  |
		#echo DEBUG :: rm -rf /nsm/zeek/logs/${OLDEST_ZEEK_LOG_DIR}
		rm -rf /nsm/zeek/logs/${OLDEST_ZEEK_LOG_DIR}
		((DELETED_ZEEK_LOGS++))
	fi
}

check-sizes
#echo ::::::: Starting Values
#print_calculated_values

# Keep original values to compare at the end
ORIG_NSM_ZEEK_LOGS_USAGE=${NSM_ZEEK_LOGS_USAGE}
ORIG_NSM_ZEEK_CRASH_USAGE=${NSM_ZEEK_CRASH_USAGE}

# Clean up Zeek's crash logs.
while [ ${NSM_ZEEK_CRASH_USAGE_PCT} -gt ${ZEEK_CRASH_MAX_PCT} ] 
do
	validate_oldest_crash_log
	if [ $(( OLDEST_CRASH_LOG_AGE + MIN_LOG_AGE )) -gt ${TS_NOW} ] ; then
		echo $(date) - Removed ${DELETED_CRASH_LOGS} folders of zeek crash logs. Cannot remove more with minimum file age at ${MIN_CRASH_LOG_AGE_DAYS} days. | tee -a ${LOG_FILE}
		break
	fi
	del_oldest_crash_log
	check-sizes
	if [ ${NSM_ZEEK_CRASH_USAGE_PCT} -lt ${ZEEK_CRASH_MAX_PCT} ] ; then
		echo $(date) - Removed ${DELETED_CRASH_LOGS} folders of zeek crash logs. Accomplished storage goals '('${ZEEK_CRASH_MAX_PCT}'%)' and retained at least ${MIN_CRASH_LOG_AGE_DAYS} days. | tee -a ${LOG_FILE}
	fi
done

# Clean up Zeek's logs.
while [ ${NSM_ZEEK_LOGS_USAGE_PCT} -gt ${ZEEK_LOGS_MAX_PCT} ] ; do
	validate_oldest_zeek_log
	if [ $(( OLDEST_ZEEK_LOG_AGE + MIN_ZEEK_LOG_AGE )) -gt ${TS_NOW} ] ; then
		echo $(date) - Removed ${DELETED_ZEEK_LOGS} days of zeek logs. Cannot remove any more with minimum file age at ${MIN_ZEEK_LOG_AGE_DAYS} days. | tee -a ${LOG_FILE}
		break
	fi
	
	del_oldest_zeek_log
	check-sizes

	if [ ${NSM_ZEEK_LOGS_USAGE_PCT} -lt ${zeek_logs_max_pct} ] ; then
		echo $(date) - Removed ${DELETED_ZEEK_LOGS} days of logs. Accomplished storage goals '('${zeek_logs_max_pct}%')' and retained at least ${MIN_ZEEK_LOG_AGE_DAYS} days. | tee -a ${LOG_FILE}
		break
	fi
	# DEBUG :: REMOVE WHEN OUT OF TESTING
	#if [ ${DELETED_ZEEK_LOGS} -gt 5 ] ; then echo "Break out of loop for test purposes" ; break ; fi
done

echo ::::::: Final Values
print_calculated_values
echo #BLANK LINE
echo Deleted ${DELETED_CRASH_LOGS} crash logs, recovered $((ORIG_NSM_ZEEK_CRASH_USAGE - NSM_ZEEK_CRASH_USAGE / 1024 ))MB space. | tee -a ${LOG_FILE}
echo Deleted ${DELETED_ZEEK_LOGS} zeek logs, recovered $((ORIG_NSM_ZEEK_LOGS_USAGE - NSM_ZEEK_LOGS_USAGE / 1024 ))MB space. | tee -a ${LOG_FILE}