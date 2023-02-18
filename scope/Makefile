# Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
# which can be found via http://creativecommons.org (and should be included as 
# LICENSE.txt within the associated archive or repository).

BOARD := $(shell if [ -e "/dev/scale-board" -a -r "/dev/scale-board" -a -w "/dev/scale-board" ] ; then echo "/dev/scale-board" ; else echo "" ; fi)
SCOPE := $(shell if [ -e "/dev/scale-scope" -a -r "/dev/scale-scope" -a -w "/dev/scale-scope" ] ; then echo "/dev/scale-scope" ; else echo "" ; fi)

ifeq "${BOARD}"   ""
  $(warning /dev/scale-board does not exist, cannot be read from or written to, or similar)
endif
ifeq "${SCOPE}"   ""
  $(warning /dev/scale-scope does not exist, cannot be read from or written to, or similar)
endif

DATA  := stage2.dat

attack   :
	@./1902783.elf --device $(shell realpath ${BOARD})
attack-ld :
	@./1902783.elf --device $(shell realpath ${BOARD}) --traces-rd ${DATA}
attack-st :
	@./1902783.elf --device $(shell realpath ${BOARD}) --traces-wr ${DATA}
