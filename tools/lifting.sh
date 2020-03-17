#!/usr/bin/env bash


LIFTED=$(mktemp)
ABIED=$(mktemp)
ENFORCED=$(mktemp)
CANONICAL_LOOPS=$(mktemp)
MEM_TO_REG=$(mktemp)
CACHE_DIR=".cache_revng"


function revng_lift_binary {
    echo "Lifting binary..." && revng-lift --use-debug-symbols --debug-info ll $1 $LIFTED && \
	echo "Isolating functions..." && revng opt -S $LIFTED -detect-function-boundaries -detect-abi -o $ABIED &&  \
	revng  opt -S $ABIED -isolate -enforce-abi -o $2 || (echo "ERROR in lifting process!\n" && exit -1) \
}

function retdec_lift_binary {
    retdec-decompiler.py --stop-after bin2llvmir -o $2 $1 || (echo "ERROR in lifting process!\n" && exit -1)
}

function optimize_lifted {
	revng opt -S $1 -loop-simplify -o $CANONICAL_LOOPS && \
	revng opt -S $CANONICAL_LOOPS -mem2reg -o $MEM_TO_REG || (echo "ERROR in lifting process!\n" && exit -1)
}

function scan_plt_section {
	${PASS_DIRECTORY}/strip_objdump_plt.sh $1 $2.plt_sec.csv
	ISOLATION_OPTIONAL_FLAGS="-dyn-rel-maps=$2.plt_sec.csv"
}

function print_usage {
	cat <<EOF
Author: Daniele Marsella <daniele.marsella@mail.polimi.it>
Revng Security Analysis wrapper script:
Usage: $0 {--with-retdec|--with-revng} file output_basename
EOF
}

scan_plt_section $2 $3

if [[ $1 == "--with-retdec" ]]
then
    retdec_lift_binary $2 $3
    mv ${3}.ll $LIFTED
elif [[ $1 == "--with-revng" ]]
then
    revng_lift_binary $2 $LIFTED
else
    print_usage
    exit 1
fi

optimize_lifted $LIFTED

mv $MEM_TO_REG ${3}.ll

sed -i "s/^;.*ModuleID.*$/; ModuleID = '$(basename $3).ll'/" ${3}.ll
