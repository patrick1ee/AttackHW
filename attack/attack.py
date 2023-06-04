# Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
# which can be found via http://creativecommons.org (and should be included as 
# LICENSE.txt within the associated archive or repository).

import  argparse, binascii, datetime, numpy, select, serial, socket, string, struct, sys, time
import picoscope.ps2000a as ps2000a
from random import randint
from textwrap import wrap

import matplotlib.pyplot as plt


PS2000A_RATIO_MODE_NONE = 0 # Section 3.18.1
PS2000A_RATIO_MODE_AGGREGATE = 1 # Section 3.18.1
PS2000A_RATIO_MODE_DECIMATE = 2 # Section 3.18.1
PS2000A_RATIO_MODE_AVERAGE = 4 # Section 3.18.1

SCOPE_RANGE_CHAN_A = 5.0E-0
SCOPE_RANGE_CHAN_B = 500.0E-3

## Pre-computed values for the AES S-box function

SBOX = [
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 
  0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 
  0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 
  0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 
  0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 
  0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 
  0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 
  0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 
  0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 
  0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 
  0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 
  0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 
  0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 
  0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 
  0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 
  0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 
  0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]


## Pre-computed hamming weight values

HW = [
  0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
  4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
]


## For use in a loop to create terminal progress bar
## \param[in] iteration current iteration
## \param[in] total     total iterations
## \param[in] prefix    prefix string
## \param[in] suffix    suffix string
## \param[in] decimals  positive number of decimals in percent complete
## \param[in] length    character length of bar
## \param[in] fill      bar fill character
## \param[in] printEnd  end character

def print_progress_bar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    if iteration == total: 
        print()


## Convert a length-prefixed, hexadecimal octet string into array of integer bytes
## 
## \param[in] x  an octet string
## \return       array of integer bytes
## \throw        ValueError if the length prefix and data do not match

def octetstr2bytes( x ) :
  b = [] ; t = x.split( ':' ) ; n = int( t[ 0 ], 16 )

  if ( n != len( t[ 1 ] ) / 2 ) :
    raise ValueError
  else :
    for i in range(0, n):
      b.append( int( t[ 1 ][ i*2 : (i+1)*2 ], 16 ) )

  return b


## Convert array of integer bytes into length-prefixed hexadecimal octet string
## 
## \param[in] X  array of integer bytes
## \return       an octet string

def byte_seq_to_octet_string( X ) :
  s = format(len(X), '02x').upper() + ":"
  for x in X:
    s += format(x, '02x').upper()
  return s


## Open  (or start)  communication with SCALE development board.
## Note the delay, which is intended to throttle (or slow down) communication
## steps, e.g., allow the connection to "settle" before continuing, and hence
## avoid certain classes of (transient) error.
##
## \return    fd a communication end-point

def board_open() :
  if   ( args.mode == 'uart'   ) :
    fd = serial.Serial( port = args.uart, baudrate = 9600, bytesize = serial.EIGHTBITS, parity = serial.PARITY_NONE, stopbits = serial.STOPBITS_ONE, timeout = None )
  elif ( args.mode == 'socket' ) :
    fd = socket.socket( socket.AF_INET, socket.SOCK_STREAM ) ; fd.connect( ( args.socket_host, args.socket_port ) ) ; fd = fd.makefile( mode = 'rwb', buffering = 1024 )

  time.sleep( args.throttle_open )

  return fd


## Close (or finish) communication with SCALE development board.
##
## \param[in] fd a communication end-point

def board_close( fd ) :
  fd.close()


## Read  (or recieve) a string from SCALE development board, automatically 
## managing CR-only EOL semantics.
## Note the delay, which is intended to throttle (or slow down) communication
## steps, e.g., allow the connection to "settle" before continuing, and hence
## avoid certain classes of (transient) error.
##
## \param[in] fd a communication end-point
## \return    r  a string (e.g., string, or bytearray)

def board_rdln( fd ) :
  r = ''

  while( True ):
    t = fd.read( 1 ).decode( 'ascii' )
    if ( args.debug ) :
      print( 'rdln> {0:s} [{1:02X}]'.format( t if ( t.isprintable() ) else ' ', ord(t) ) )

    if( t == '\x0D' ) :
      break
    else:
      r += t

  if   ( args.force_upper ) :
    r = r.upper()
  elif ( args.force_lower ) :
    r = r.lower()

  if ( args.debug ) :
    print( 'rdln> {0:s}'.format( r ) )

  time.sleep( args.throttle_rd )

  return r


## Write (or send)    a string to   SCALE development board, automatically 
## managing CR-only EOL semantics.
## Note the delay, which is intended to throttle (or slow down) communication
## steps, e.g., allow the connection to "settle" before continuing, and hence
## avoid certain classes of (transient) error.
##
## \param[in] fd a communication end-point
## \param[in] x  a string (e.g., string, or bytearray)

def board_wrln( fd, x ) :
  if   ( args.force_upper ) :
    x = x.upper()
  elif ( args.force_lower ) :
    x = x.lower()

  fd.write( ( x ).encode( 'ascii' ) ) ; fd.flush()

  if ( args.debug ) :
    print( 'wrln> {0:s}'.format( x ) )

  time.sleep( args.throttle_wr )


## Initialise and open oscilloscope
##
## \return scope         PS2000a instance which is ready to use
## \return num_samples   number of samples in given sampling interval
## \return scope_adc_max maximum ADC count in GetValues calls
## \return scope_adc_min minimum ADC count in GetValues calls

def setup_scope():
  # Phase 1 follows Section 2.7.1.1 of the 2206B programming guide , producing
  # a 1-shot block mode acquisition process : it configures the 2206B to
  #
  # - wait for a trigger signal (a positive edge exceeding 2 V) on channel A,
  # - sample from both channel A and B, using appropriate voltage ranges and
  # for an appropriate amount of time (i.e., ~2 ms),
  # - store the resulting data in buffers with no post - processing (e.g., with
  # no downsampling ).

  try :
    # Section 3.32 , Page 60; Step 1: open the oscilloscope
    scope = ps2000a . PS2000a ()

    # Section 3.28 , Page 56
    scope_adc_min = scope . getMinValue ()
    # Section 3.30 , Page 58
    scope_adc_max = scope . getMaxValue ()

    # Section 3.39 , Page 69; Step 2: configure channels
    scope. setChannel ( channel = 'A', enabled = True , coupling = 'DC', VRange = SCOPE_RANGE_CHAN_A )
    scope. setChannel ( channel = 'B', enabled = True , coupling = 'DC', VRange = SCOPE_RANGE_CHAN_B )

    # Section 3.13 , Page 36; Step 3: configure timebase
    ( _, num_samples , samples_max ) = scope . setSamplingInterval ( 4.0E-9, 2.0E-3 )

    # Section 3.56 , Page 93; Step 4: configure trigger
    scope. setSimpleTrigger ( 'A', threshold_V = 2.0E-0, direction = 'Rising', timeout_ms = 0 )

    return scope, num_samples, scope_adc_max, scope_adc_min

  except Exception as e :
    raise e


## Generate an octetstring of N bytes
## \param[in] N integer size of required number of bytes
## \return r resulting octetstring

def generate_octet_str( N ):
  b = []
  for i in range( N ):
    b.append( randint( 0, 255 ) )
  r = byte_seq_to_octet_string(b)
  return r


## Acquire the params required by the device, namely SIZEOF_BLK and SIZEOF_RND
##
## \param[in] fd            a communication end-point for the SCALE board
## \return SIZEOF_BLK       required plaintext size in bytes as an integer
## \return SIZEOF_RND       required randomness size in bytes as an integer

def acquire_params( fd ):
  board_wrln(fd, "01:00\r")
  blk_param = board_rdln( fd )
  key_param = board_rdln( fd )
  rnd_param = board_rdln( fd )
  return octetstr2bytes(blk_param)[0], octetstr2bytes(rnd_param)[0]


## Acquire trace using picoscope
##
## \param[in] scope         picoscope instance of PS2000A, representing oscilloscope
## \param[in] fd            a communication end-point for the SCALE board
## \param[in] m             randomly generated plaintext to use for encryption trace
## \param[in] num_samples   integer representing number of samples to acquire
## \param[in] scope_adc_max maximum ADC count in GetValues calls
## \param[in] scope_adc_min minimum ADC count in GetValues calls
## \param[in] SIZEOF_BLK    required plaintext size in bytes
## \param[in] SIZEOF_RND    required randomness size in bytes
## \return    c             resulting ciphertext from encryption
## \return    trace_size    integer representing size of final trace (filtering out values where the trigger is below the threshold)
## \return    A             array of samples from channel A (trigger signal)
## \return    B             array of samples from channel B (acquisition signal)

def acquire_trace( scope, fd, m, num_samples, scope_adc_max, scope_adc_min, SIZEOF_BLK, SIZEOF_RND ):

  try :
    # Section 3.37 , Page 65; Step 5: start acquisition
    scope. runBlock ()

    # Pass encryption command, message and randomness inputs to target
    board_wrln(fd, "01:01\r")
    board_wrln(fd, generate_octet_str(SIZEOF_BLK) + "\r")
    board_wrln(fd, generate_octet_str(SIZEOF_RND) + "\r")
  
    # Section 3.26 , Page 54; Step 6: wait for acquisition to complete
    while ( not scope . isReady () ) : time. sleep ( 0.0001 )

    # Section 3.40 , Page 71; Step 7: configure buffers
    # Section 3.18 , Page 43; Step 8; transfer buffers
    ( A, _, _ ) = scope . getDataRaw ( channel = 'A', numSamples = num_samples , downSampleMode = PS2000A_RATIO_MODE_NONE )
    ( B, _, _ ) = scope . getDataRaw ( channel = 'B', numSamples = num_samples , downSampleMode = PS2000A_RATIO_MODE_NONE )

    # Section 3.2 , Page 25; Step 10: stop acquisition
    scope.stop ()

  except Exception as e :
    raise e

  # Phase 2 simply stores the acquired data (both channels A *and* B) into a
  # CSV - formated file named on the command line.

  r = board_rdln( fd )
  c =                  octetstr2bytes( r )

  trace_A = []
  trace_B = []
  trace_size = 0
  
  for i in range( num_samples ) :
    A_i = ( float( A[ i ] ) / float ( scope_adc_max ) ) * SCOPE_RANGE_CHAN_A
    if A_i >= 2.0:
      trace_A.append( A[ i ] )
      trace_B.append( B[ i ] )
      trace_size += 1

  return c, trace_size, trace_A, trace_B


## Acquire series of traces from encrypting random plaintexts
## 
## \param[in] num_traces  the number of traces to acquire
## \return    t           the number of acquired traces
## \return    s           the number of samples in each trace
## \return    M           a t-by-16 matrix of AES-128  plaintexts
## \return    C           a t-by-16 matrix of AES-128 ciphertexts
## \return    T           a t-by-s  matrix of samples, i.e., the traces

def acquire_encryption_traces( num_traces ) :
  M = [] ; C = [] ; T = [] ; t = 0 ; prev_trace_size = 1000000

  fd = board_open()
  scope, num_samples, scope_adc_max, scope_adc_min = setup_scope()

  for i in range( num_traces ):

    m = generate_plaintext()
    c, trace_size, A, B = acquire_trace( scope, fd, m, num_samples, scope_adc_max, scope_adc_min, SIZEOF_BLK, SIZEOF_RND )

    ## Ensure all traces are of the same size
    if trace_size < prev_trace_size and t > 0:
      for j in range(0, t):
        T[ j ] = T[ j ][ : trace_size ]
      prev_trace_size = trace_size
    elif trace_size > prev_trace_size:
      B = B[ : prev_trace_size ]

    M.append( m ) ; C.append( c ) ; T.append( B ) ; t += 1 ; s = prev_trace_size
    print_progress_bar(i, num_traces, prefix='Acquring traces ', suffix='Complete', length=50)

  print('\n')
  board_close( fd )
  scope.close()

  return num_traces, prev_trace_size, M, C, T


## Prepares the acquired trace arrays to be written to a dat file
## 
## \param[in] t the number of acquired traces
## \param[in] M a t-by-16 matrix of AES-128  plaintexts
## \param[in] C a t-by-16 matrix of AES-128 ciphertexts
## \param[in] T a t-by-s  matrix of samples, i.e., the traces

def format_trace_arrays( t, M, C, T):
  M_f =  numpy.zeros( ( t, 16 ), dtype =  numpy.uint8 )
  C_f =  numpy.zeros( ( t, 16 ), dtype =  numpy.uint8 )
  T_f =  numpy.zeros( ( t,  len(T[0]) ), dtype =  numpy.int16 )

  for i in range(0, t):
    M_f[ i ] = M[ i ] ; C_f[ i ] = C[ i ] ; T_f[ i ] = T[ i ]
  return M_f, C_f, T_f
 

## Load  a trace data set from an on-disk file.
## 
## \param[in] f the filename to load  trace data set from
## \return    t the number of traces
## \return    s the number of samples in each trace
## \return    M a t-by-16 matrix of AES-128  plaintexts
## \return    C a t-by-16 matrix of AES-128 ciphertexts
## \return    T a t-by-s  matrix of samples, i.e., the traces

def traces_ld( f ) :
  fd = open( f, "rb" )

  def rd( x ) :
    ( r, ) = struct.unpack( x, fd.read( struct.calcsize( x ) ) ) ; return r

  t = rd( '<I' )
  s = rd( '<I' )

  M =  numpy.zeros( ( t, 16 ), dtype =  numpy.uint8 )
  C =  numpy.zeros( ( t, 16 ), dtype =  numpy.uint8 )
  T =  numpy.zeros( ( t,  s ), dtype =  numpy.int16 )

  for i in range( t ) :
    for j in range( 16 ) :
      M[ i, j ] = rd( '<B' )

  for i in range( t ) :
    for j in range( 16 ) :
      C[ i, j ] = rd( '<B' )

  for i in range( t ) :
    for j in range( s  ) :
      T[ i, j ] = rd( '<h' )
    print_progress_bar(i, t, prefix='Loading trace data ', suffix='Complete', length=50)

  fd.close()

  return t, s, M, C, T


## Store a trace data set into an on-disk file.
## 
## \param[in] f the filename to store trace data set into
## \param[in] t the number of traces
## \param[in] s the number of samples in each trace
## \param[in] M a t-by-16 matrix of AES-128  plaintexts
## \param[in] C a t-by-16 matrix of AES-128 ciphertexts
## \param[in] T a t-by-s  matrix of samples, i.e., the traces

def traces_st( f, t, s, M, C, T ) :
  fd = open( f, "wb" )

  def wr( x, y ) :
    fd.write( struct.pack( x, y ) )

  wr( '<I', t   )
  wr( '<I', s   )

  for i in range( t ) :
    for j in range( 16 ) :
      wr( '<B', M[ i, j ] )

  for i in range( t ) :
    for j in range( 16 ) :
      wr( '<B', C[ i, j ] )

  for i in range( t ) :
    for j in range( s  ) :
      wr( '<h', T[ i, j ] )

  print('\n')
  fd.close()


## Truncate each trace in a given matrix by removing samples outside a given range
## 
## \param[in] T a t-by-s  matrix of samples, i.e., the traces
## \param[in] t the number of traces
## \param[in] start the lower bound of the range to retain
## \param[in] start the upper bound of the range to retain
## \return    s the new number of samples in each truncated trace
## \return    T_t a t-by-s  matrix of the truncated samples, i.e., the new traces

def truncate_trace_samples( T, t, start, end ):
  T_t = T[:,range(start, end)]
  return end - start, T_t


## Compress each trace in a given matrix by averaging out the samples over a given range
## 
## \param[in] T   a t-by-s  matrix of samples, i.e., the traces
## \param[in] t   the number of traces
## \param[in] s   the number of samples in each trace
## \param[in] n   the range over which to create averages over
## \return    sn  the new number of samples in each compressed trace
## \return    T_t a t-by-s  matrix of the compressed samples, i.e., the new traces

def compress_trace_samples( T, t, s, n ):
  T_t = []
  for i in range(0, t):
    T_s = []
    for j in range(0, int(s / n)):
      mean = 0
      for k in range(0, n):
        mean += T[i][j*n + k]
      T_s.append(mean / n)
    T_t.append(T_s)
    sn = int(s / n)
    print_progress_bar(i, t, prefix='Compressing trace samples ', suffix='Complete', length=50)
  return sn, T_t


## Generates a hyptohesis for each possible byte of the encyption key, given a list of messages
## 
## \param[in] M     array of messages to use
## \param[in] b     integer representing the hypothetical key byte
## \param[in] track boolean determining whether or not to output progress bar
## \return    h     the number of hypothetical key bytes
## \return    H     t-by-h matrix of hypothesied traces

def generate_hypothesis_matrix( M, b ):
  h = 256
  H = []
  for m in M:
    Hn = []
    for j in range(0, h):
      a = SBOX[m[b] ^ j]
      Hn.append(HW[a])
    H.append(Hn)
  return h, numpy.array(H)
    

## Uses einstein summations to generate a correlation matrix between the real and hypthetical trace matrices,
## also finding the hypothetical key byte which results in the maximum correlation
##
## \param[in] R   matrix of real traces
## \param[in] H   matrix of hypothetical traces
## \param[in] t   number of traces in both real and hypothetical matrices
## \param[in] h   the number of hypothesis used in the hypothesis matrix
## \return    C   the h-by-s correlation matrix
## \return    max the hypothetical key byte which resulted in the maximum correlation

def destinguish_hypothesis( R, H, t, s, h ):                                                                                                                                                                       

  H_norm = H - (numpy.einsum("th->h", H, optimize='optimal') / numpy.double(t))
  R_norm = R - (numpy.einsum("ts->s", R, optimize='optimal') / numpy.double(t))

  H_var = numpy.einsum("th,th->h", H_norm, H_norm, optimize='optimal')
  R_var = numpy.einsum("ts,ts->s", R_norm, R_norm, optimize='optimal')
  HR_var_sqrt = numpy.sqrt(numpy.einsum("h,s->hs", H_var, R_var, optimize='optimal'))

  C = numpy.einsum("th,ts->hs", H_norm, R_norm, optimize='optimal') / numpy.double(HR_var_sqrt)

  max_found = (0, 0.0)
  C_abs = numpy.absolute(C)
  for i in range(0, h):
    new_max = max(C_abs[i])
    if new_max > max_found[1]:
      max_found = (i, new_max)

  return C, max_found


## Outputs the correlation graph for each key byte hypothesis
##
## \param[in] C the correlation matrix
## \return    s the number of samples in each matrix

def output_correlation_graph(C, s):
  for i in range(0, len(C)):
    plt.plot(numpy.arange(0, s), C[i])
    plt.xlabel('Samples')
    plt.ylabel('Correlation')
    plt.savefig(str(i) + '-corr')
    print_progress_bar(i, len(C), prefix='Progress', suffix='Complete', length=50)


## Attack implementation, as invoked from main after checking command line
## arguments.
##
## \param[in] argc number of command line arguments
## \param[in] argv           command line arguments

def attack( argc, argv ) :
  if args.trace_set is None:
    t, s, M, C, T = acquire_encryption_traces(1000)
  else:
    t, s, M, C, T = traces_ld( args.trace_set )

  M, C, T = format_trace_arrays(t, M, C, T)
  T = numpy.array(T)

  dts = time.time()
  s, T = truncate_trace_samples(T, t, 0, 25000)
  s, T = compress_trace_samples(T, t, s, 20)
  dte = time.time()
  time_pre_processing = dte - dts

  key_bytes = []
  max_coeffs = []

  dts = time.time()

  for i in range(0, 16):
    h, H = generate_hypothesis_matrix( M, i )

    C, max_found = destinguish_hypothesis( T, H, t, s, h )
    key_bytes.append(max_found[0])
    max_coeffs.append(max_found[1])

    print_progress_bar(i, 15, prefix='Creating correlation matrix ', suffix='Complete', length=50)

  dte = time.time()
  time_analysis = dte - dts

  print('\n\n')
  print('Found key: ' + byte_seq_to_octet_string(key_bytes) + '\n')
  print('Confidence (mean correlation strength): ' + str(numpy.mean(max_coeffs)) + '\n')
  print('Number of traces used: ' + str(t) + '\n')
  print('Number of samples per trace (after compression): ' + str(s) + '\n')
  print('Pre-processing time: ' + str(time_pre_processing) + 's\n')
  print('Analysis time: ' + str(time_analysis) + 's\n')


if ( __name__ == '__main__' ) :
  parser = argparse.ArgumentParser()
  parser.add_argument( '--debug',         dest = 'debug',                     action = 'store_true',                            default = False           )
  parser.add_argument( '--mode',          dest = 'mode',                      action = 'store', choices = [ 'uart', 'socket' ], default = 'uart'             )
  parser.add_argument( '--data',          dest = 'data',          type = str, action = 'store',                                 default = None               )
  parser.add_argument( '--uart',          dest = 'uart',          type = str, action = 'store',                                 default = '/dev/scale-board' )
  parser.add_argument( '--socket-host',   dest = 'socket_host',   type = str, action = 'store',                                 default = '127.0.0.1'              )
  parser.add_argument( '--socket-port',   dest = 'socket_port',   type = int, action = 'store',                                 default = '1234'               )
  parser.add_argument( '--throttle-open', dest = 'throttle_open', type = int, action = 'store',                                 default = 0.001                )
  parser.add_argument( '--throttle-rd',   dest = 'throttle_rd',   type = int, action = 'store',                                 default = 0.001                )
  parser.add_argument( '--throttle-wr',   dest = 'throttle_wr',   type = int, action = 'store',                                 default = 0.001             )
  parser.add_argument( '--force-upper',   dest = 'force_upper',               action = 'store_true',                            default = False              )
  parser.add_argument( '--force-lower',   dest = 'force_lower',               action = 'store_true',                            default = False              )
  parser.add_argument( '--trace-set',      dest = 'trace_set',     type = str, action = 'store',                                default = None )
  args = parser.parse_args()

  attack( len( sys.argv ), sys.argv )



