#!/bin/bash

SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd -P)"
WS="$SCRIPT_PATH"
SOURCE_DIR="$WS/linux-5.9"

LINKSCRIPT="arch/x86/kernel/vmlinux.lds.S"
INSERTPOINT="(.fixup)"

NK_COMMENT="\t\t/* nested kernel */"
NK_TEXT="\t\t. = ALIGN(PAGE_SIZE);\n\t\tALIGN_FUNCTION(); __nk_text_start = .; *(.nk.text) __nk_text_end = .;\n\t\t. = ALIGN(PAGE_SIZE);"

sed -i '/'"$INSERTPOINT"'/i\'"$NK_COMMENT"'' "$SOURCE_DIR/$LINKSCRIPT"
sed -i '/'"$INSERTPOINT"'/i\'"$NK_TEXT"'' "$SOURCE_DIR/$LINKSCRIPT"
