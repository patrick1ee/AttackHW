# Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
# which can be found via http://creativecommons.org (and should be included as 
# LICENSE.txt within the associated archive or repository).

BOARD := $(shell if [ -e "/dev/scale-board" -a -r "/dev/scale-board" -a -w "/dev/scale-board" ] ; then echo "/dev/scale-board" ; else echo "" ; fi)

ifeq "${BOARD}"   ""
  $(warning /dev/scale-board does not exist, cannot be read from or written to, or similar)
endif

ifeq "${REPO}"    ""
  $(warning REPO    environment variable is not set)
endif
ifeq "${TARGET}"  ""
  $(warning TARGET  environment variable is not set)
endif
ifeq "${PROJECT}" ""
  $(warning PROJECT environment variable is not set)
endif

  build         :
	@make --file="${REPO}/build/${TARGET}/lib/scale.mk" BSP="${REPO}/build/${TARGET}" USB="$(shell realpath ${BOARD})" PROJECT="${PROJECT}" build
  clean         :
	@make --file="${REPO}/build/${TARGET}/lib/scale.mk" BSP="${REPO}/build/${TARGET}" USB="$(shell realpath ${BOARD})" PROJECT="${PROJECT}" clean
program         :
	@make --file="${REPO}/build/${TARGET}/lib/scale.mk" BSP="${REPO}/build/${TARGET}" USB="$(shell realpath ${BOARD})" PROJECT="${PROJECT}" program
emulate         :
	@make --file="${REPO}/build/${TARGET}/lib/scale.mk" BSP="${REPO}/build/${TARGET}" USB="$(shell realpath ${BOARD})" PROJECT="${PROJECT}" emulate

 putty-physical :
	@make --file="${REPO}/build/${TARGET}/lib/scale.mk" BSP="${REPO}/build/${TARGET}" USB="$(shell realpath ${BOARD})" PROJECT="${PROJECT}" putty-physical
 putty-emulated :
	@make --file="${REPO}/build/${TARGET}/lib/scale.mk" BSP="${REPO}/build/${TARGET}" USB="$(shell realpath ${BOARD})" PROJECT="${PROJECT}" putty-emulated
