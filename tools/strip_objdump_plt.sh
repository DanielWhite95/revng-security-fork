#!/bin/bash

OBJDUMP_BIN=$(which objdump)
OBJDUMP_FLAGS="-M intel -D"

help_usage()  {
    printf "Utility that parses input object file to obtain plt location usign objdump\n"
    printf "\n\nUsage: strip_objdump_plt file [output_file]\n\n"
}


INPUT_OBJECT="$1"
OUTPUT_OBJECT="$2"

[[ $1 ]] && [[ $2 ]] || (echo "Invalid input! '--help' for more information" ;exit -1)

$OBJDUMP_BIN -R $INPUT_OBJECT | sed "1,5 d" |  sed "s/@.*$//" | sed "s/^0\+//" | sed "s/[[:space:]]\+/ /g" | cut -d " " -f 1,3 | tr " " "," | sed -r '/^\s*$/d' > $OUTPUT_OBJECT
printf "Printed mappings of relocations to $2\n"
