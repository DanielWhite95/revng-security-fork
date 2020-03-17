#!/usr/bin/env bash
for last; do true; done ## FETCH LAST COMMAND ARGUMENT
INPUT_FILE=$last

## OPTIONAL FLAGS
REVNG_DEBUG_OPTION=""
ISOLATION_OPTIONAL_FLAGS=""
MARKED_OPT_FLAG=""
INPUT_FUNCTIONS_FILE=$HOME/workdir/input_functions.csv
DUMP_SECURITY_JSON_FLAG=""
DUMP_TAINT_JSON_FLAG=""

## RESOURCE USAGE VARS
LIFT_TIME=""
BACKPROP_TIME=""
ANALYSIS_TIME=""

function print_usage {
	cat <<EOF
Author: Daniele Marsella <daniele.marsella@mail.polimi.it>
Revng Security Analysis wrapper script:
Usage: $0 [-m] [-c] [-i input_functions] [-j json_file] binaryfile
	-m 			Analyze only functions reached by input functions
	-c			Clean cached results before analysis
	-i input_functions	Read input functions from input_functions file
        -j json_file            Dump security analysis JSON to json_file
        -t taint_json_file      Dump taint analysis JSON to taint_json_file

Result files:
	- ${RESULT_SECURITY_JSON} 	JSON of the security analysis result
	- ${RESULT_TAINT_JSON}	 	JSON of the taint analysis result
        - ${MARKED}			LLVM IR with marked input functions

EOF
}



function scan_ll {
	echo "Starting analysis..."
	echo "Logging info on file ${RESULT_DBG}..."
	## MARK INPUT FUNCTIONS IN LL AND PROPAGATED THEM IN CALLGRAPH
	PROPAGATED_FILE=$(mktemp -d)/propagated.ll
	BACKPROP_TIME=$(revng ${REVNG_DEBUG_OPTION} opt -S $1 -stats -input-functions-csv=${INPUT_FUNCTIONS_FILE?"Missing input functions file"} ${ISOLATION_OPTIONAL_FLAGS}  ${ONLY_REVNG_FUNCTIONS} ${DUMP_TAINT_JSON_FLAG} -revng-max-cg-length -revng-backward-prop -o $PROPAGATED_FILE)
	## SCAN MARKED LL
	ANALYSIS_TIMING=$(revng opt -S $PROPAGATED_FILE ${REVNG_DEBUG_OPTION} -stats ${DUMP_SECURITY_JSON_FLAG} -input-functions-csv=${INPUT_FUNCTIONS_FILE?"Missing input functions file"} ${ONLY_REVNG_FUNCTIONS} -revng-security-analysis -o /dev/null)

	if [[ $? -eq 0 ]]
	then
	    echo "Analysis results printed to $RESULT_PREFIX.txt"
	else
	    echo -e "Something went wrong, please check that environment variables are set correctly:\n- PASS_DIRECTORY\n- PROGRAM_DIRECTORY"
	fi
}


function print_times {
    echo "Time for lifting binary: "
    echo $LIFT_TIME
    echo "------------------------"
    echo "Time for input backward propagation: "
    echo $BACKPROP_TIME
    echo "------------------------"
    echo "Time for buffer overflow anlaysis: "
    echo $ANALYSIS_TIME
}


### MAIN


while getopts "cmi:j:rt:" option; do
    case ${option} in
	c ) # Remove analysis cache
	    echo "Cleaning analysis cache..."
	    rm -f "${RESULT_PREFIX}*"
	    rm -rf ${CACHE_DIR}
	    ;;
	i ) # Override default input function file
	    INPUT_FUNCTIONS_FILE=${OPTARG?"Missing input functions file name"}
	    ;;
	m ) # Analyze only marked functions
	    echo "Analyzing only functions reached by input"
	    MARKED_OPT_FLAG="-only-marked-funs"
	    ;;
	j ) # Override JSON output filename
	    RESULT_SECURITY_JSON=${OPTARG?"Missing json filename"}
	    DUMP_SECURITY_JSON_FLAG="-dump-result -dump-result-file=${RESULT_SECURITY_JSON} -rfp -ldp"
	    ;;
	t ) # Taint JSON output filename
	    RESULT_TAINT_JSON=${OPTARG?"Missing taint json filename"}
	    DUMP_TAINT_JSON_FLAG="-taint-json-file=${RESULT_TAINT_JSON} "
	    ;;
	r )
	    ONLY_RENG_FUNCTIONS="-only-revng-loops"
	    ;;
	\? ) #For invalid option
	    print_usage
	    ;;
    esac
done

scan_ll $INPUT_FILE

print_times
