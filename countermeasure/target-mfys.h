/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#ifndef __TARGET_H
#define __TARGET_H

#include <stdlib.h>
#include <sys/time.h>

#include <scale/scale.h>

#define COMMAND_INSPECT ( 0x00 )
#define COMMAND_ENCRYPT ( 0x01 )
#define COMMAND_TEST    ( 0x02 )

#define SIZEOF_BLK      (   16 )
#define SIZEOF_KEY      (   16 )
#define SIZEOF_RND      (   48 )

#endif
