# Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
# which can be found via http://creativecommons.org (and should be included as 
# LICENSE.txt within the associated archive or repository).

import  argparse, binascii, numpy select, serial, socket, string, struct, sys, time
import picoscope.ps2000a as ps2000a
import random.randint as randint

import matplotlib.pyplot as plt

SIZE_OF_BLK = 16
SIZE_OF_KEY = 16

PS2000A_RATIO_MODE_NONE = 0 # Section 3.18.1
PS2000A_RATIO_MODE_AGGREGATE = 1 # Section 3.18.1
PS2000A_RATIO_MODE_DECIMATE = 2 # Section 3.18.1
PS2000A_RATIO_MODE_AVERAGE = 4 # Section 3.18.1

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

def print_progress_bar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()


## Convert a byte string (e.g., bytearray) into a sequence (or list) of bytes.
## 
## \param[in] x  a  byte  string
## \return       a  byte  sequence

def bytes2seq( x ) :
  return            [ int( t ) for t in x ]

## Convert a sequence (or list) of bytes into a byte string (e.g., bytearray).
## 
## \param[in] x  a  byte  sequence
## \return       a  byte  string

def seq2bytes( x ) :
  return bytearray( [ int( t ) for t in x ] )

## Convert a length-prefixed, hexadecimal octet string into a byte string.
## 
## \param[in] x  an octet string
## \return       a  byte  string
## \throw        ValueError if the length prefix and data do not match

def octetstr2bytes( x ) :
  t = x.split( ':' ) ; n = int( t[ 0 ], 16 ) ; x = binascii.a2b_hex( t[ 1 ] )

  if ( n != len( x ) ) :
    raise ValueError
  else :
    return x

## Convert a byte string into a length-prefixed, hexadecimal octet string.
## 
## \param[in] x  an octet string
## \return       a  byte  string

def bytes2octetstr( x ) :
  n = '{0:02X}'.format( len( x ) ) ; x = binascii.b2a_hex( x ).decode( 'ascii' ).upper()

  return n + ':' + x

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
    t = fd.read( 1 )
    if ( args.debug ) :
      print( 'rdln> {0:s} [{1:02X}]'.format( t if ( t.isprintable() ) else ' ', t ) )

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


## Read  (or recieve) an array from SCALE development board, automatically 
##
## \param[in] fd a communication end-point
## \param[in] n  number of bytes to read
## \return    r  an array of byte

def board_rdbytes( fd, n ) :
  r = []

  for i in range(0, n):
    t = fd.read( 1 )
    r.append( t )

  time.sleep( args.throttle_rd )

  return r


## Write an array of bytes to SCALE development board
##
## \param[in] fd     a communication end-point
## \param[in] bytes  array of bytes to write
## \param[in] n      number of bytes to write

def board_wrbytes( fd, bytes, n ) :
  r = []

  for i in range(0, n):
    fd.write( ( i.to_bytes(1, "big")) ) ; fd.flush()
    
  time.sleep( args.throttle_wr )


## Generate random plaintext of SIZE_OF_BLK bytes
##
## \return m randomly generated plaintext

def generate_plaintext():
  m = []
  for i in range( SIZE_OF_BLK ):
    m.append( randint( 0, 256 ) )
  return m

## Acquire trace using picoscope
##
## \param[in] num_samples integer representing number of samples to acquire
## \return    trace_size  integer representing size of final trace (filtering out values where the trigger is below the threshold)
## \return    A           array of samples from channel A (trigger signal)
## \return    B           array of samples from channel B (acquisition signal)

def acquire_trace( num_samples ):
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
  scope. setChannel ( channel = 'A', enabled = True , coupling = 'DC', VRange = 5.0E -0 )
  scope_range_chan_a = 5.0e -0
  scope. setChannel ( channel = 'B', enabled = True , coupling = 'DC', VRange = 500.0E -3 )
  scope_range_chan_b = 500.0e -3

  # Section 3.13 , Page 36; Step 3: configure timebase
  #( _, samples , samples_max ) = scope . setSamplingInterval ( 4.0E-9, 2.0E -3 )

  # Section 3.56 , Page 93; Step 4: configure trigger
  scope. setSimpleTrigger ( 'A', threshold_V = 2.0E-0, direction = 'Rising ', timeout_ms = 0 )

  # Section 3.37 , Page 65; Step 5: start acquisition
  scope. runBlock ()

  # Section 3.26 , Page 54; Step 6: wait for acquisition to complete
  while ( not scope . isReady () ) : time. sleep ( 1 )

  # Section 3.40 , Page 71; Step 7: configure buffers
  # Section 3.18 , Page 43; Step 8; transfer buffers
  ( A, _, _ ) = scope . getDataRaw ( channel = 'A', numSamples = num_samples , downSampleMode = PS2000A_RATIO_MODE_NONE )
  ( B, _, _ ) = scope . getDataRaw ( channel = 'B', numSamples = num_samples , downSampleMode = PS2000A_RATIO_MODE_NONE )

  # Section 3.2 , Page 25; Step 10: stop acquisition
  scope.stop ()

  # Section 3.2 , Page 25; Step 13: close the oscilloscope
  scope.close ()

  except Exception as e :
    raise e

  # Phase 2 simply stores the acquired data (both channels A *and* B) into a
  # CSV - formated file named on the command line.

  trace_A = []
  trace_B = []
  trace_size = 0
  
  for i in range( samples ) :
    A_i = ( float( A[ i ] ) / float ( scope_adc_max ) ) * scope_range_chan_a
    B_i = ( float( B[ i ] ) / float ( scope_adc_max ) ) * scope_range_chan_b
    if B_i < 2.0:
      trace_size = i
      break
    else:
      trace_A.append( A_i )
      trace_B.append( B_i )

  return trace_size, trace_A, trace_B


## Acquire series of traces from encrypting random plaintexts
## 
## \param[in] num_samples the number of intial samples to record for each trace
## \param[in] num_traces  the number of traces to acquire
## \return    t           the number of acquired traces
## \return    s           the number of samples in each trace
## \return    M           a t-by-16 matrix of AES-128  plaintexts
## \return    C           a t-by-16 matrix of AES-128 ciphertexts
## \return    T           a t-by-s  matrix of samples, i.e., the traces

def acquire_encryption_traces( num_samples, num_traces ) :
  M = [] ; C = [] ; T = [] ; t = 0 ; s = num_samples ; prev_trace_size = num_samples
  fd = board_open()
  for i in range( num_traces ):
    m = generate_plaintext()
    board_wrbytes( fd, [ 0x31 ], 1 )
    board_wrbytes( fd, m, SIZE_OF_BLK )
    trace_size, A, B = acquire_trace( num_samples )
    r = board_rdbytes( fd, SIZE_OF_BLK )

    ## Ensure all traces are of the same size
    if trace_size < prev_trace_size and t > 0:
      T[ t - 1 ] = T[ t - 1][ : prev_trace_size - trace_size ]
      prev_trace_size = trace_size

    M.append( m ) ; C.append( c ) ; T.append( B ) ; t += 1 ; s = prev_trace_size

  board_close( fd )
  return t, s, M, C, T


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
  T_t = []
  for i in range(0, t):
    T_s = []
    for j in range(start, end):
      T_s.append(T[i][j])
    T_t.append(T_s)
  s = end - start
  return s, T_t


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
  return sn, T_t


## Generates a hyptohesis for each possible byte of the encyption key, given a list of messages
## 
## \param[in] M     array of messages to use
## \param[in] b     integer representing the hypothetical key byte
## \param[in] k     integer representing the size in bytes of the key
## \param[in] track boolean determining whether or not to output progress bar
## \return    H     t-by-h matrix of hypothesied traces
## \return    h     the number of hypothetical key bytes

def generate_hypothesis_matrix( M, b, k, track=False ):
  h = k
  H = []
  count = 0
  for m in M:
    Hn = []
    for j in range(0, h):
      a = SBOX[m[b] ^ j]
      Hn.append(HW[a])
    H.append(Hn)
    if track:
      count += 1
      print_progress_bar(count, len(M), prefix='Progress', suffix='Complete', length=50)
  return h, H
    

## Pre-computes components required for computing the pearson correlation coeffecient of vector X with an unkown vector
## 
## \param[in] X           vector to pre-compute pearson components
## \return    X_norm      vector of the same shape as X containing the normalised values of X (mean subtracted)
## \return    X_norm_sqrt float representing the root of the summation of squared normalised values of X

def get_col_pearson_factors(X):
  u = numpy.mean(X)
  X_norm = []
  X_norm_sqrt = 0
  for x in X:
    xn = x - u
    X_norm.append(xn)
    X_norm_sqrt += xn ** 2
  return X_norm, numpy.sqrt(X_norm_sqrt)


## Pre-computes components required for computing the pearson correlation coeffecients of the columns of matrix X with the columns of unknown matrix
## 
## \param[in] X           vector to pre-compute pearson components
## \param[in] track       boolean determining whether or not to output progress bar
## \return    X_cpf       matrix X with each column normalised
## \return    X_cpf_sqrt  vector containing the root of the summation of squared normalised values for each column of X

def get_col_pearson_factors_matrix(X, track=False):
  X = numpy.transpose(X)
  X_cpf = []
  X_cpf_sqrt = []
  count = 0
  for x in X:
    xn, xns = get_col_pearson_factors(x)
    X_cpf.append(xn)
    X_cpf_sqrt.append(xns)
    if track:
      count += 1
      print_progress_bar(count, len(X), prefix='Progress', suffix='Complete', length=50)
  return X_cpf, X_cpf_sqrt


## Gets correlation at point i,j between hypothetical and real trace matrix
## 
## \param[in] H_cpf       the matrix of normalised vectors from the the hypothesis matrix
## \param[in] H_cpf_sqrt  the vector of total squared normalised summations from the hypothesis matrix
## \param[in] H_cpf       the matrix of normalised vectors from the the real trace matrix
## \param[in] H_cpf_sqrt  the vector of total squared normalised summations from the real trace matrix
## \param[in] i           row of correlation matrix
## \param[in] j           row of correlation matrix
## \param[in] t           the number of traces
## \return    corr        pearson correlation coeffecient at point i,j

def get_correlation_at_point(H_cpf, H_cpf_sqrt, R_cpf, R_cpf_sqrt, i, j, t):
  HR = 0
  for x in range(0, t):
    HR += H_cpf[i][x] * R_cpf[j][x]
  corr = HR / ( H_cpf_sqrt[i] * R_cpf_sqrt[j])
  return corr


def disinguish_hypothesis( R, H, t, s, h, kb, H_cpf, H_cpf_sqrt, R_cpf, R_cpf_sqrt, track=False ):                                                                                                                                                                       
  C = []
  R =  numpy.transpose(R)
  H =  numpy.transpose(H)
  max = (0, 0.0)
  for i in range(0, h):
    C_row = [] 
    for j in range(0, s):
      corr = get_correlation_at_point(H_cpf, H_cpf_sqrt, R_cpf, R_cpf_sqrt, i, j, t)
      C_row.append(abs(corr))
      if abs(corr) > max[1]:
        max = (i, abs(corr))
      if track:
        print_progress_bar(i*s + j, h*s, prefix='Progress', suffix='Complete', length=50)
    C.append(C_row)
  
  return C, max


def output_correlation_graph(C):
  for i in range(0, len(C)):
    plt.plot(numpy.arange(0, s), C[j])
    plt.xlabel('Samples')
    plt.ylabel('Correlation')
    plt.savefig(str(i) + '-corr')
    print_progress_bar(i, len(C), prefix='Progress', suffix='Complete', length=50)


## Attack implementation, as invoked from main after checking command line
## arguments.
##
## \param[in] argc number of command line arguments
## \param[in] argv           command line arguments

#s = 82560
#provisional key: [211, 133, 51, 70, 2, 139, 110, 36, 134, 98, 233, 149, 171, 104, 126, 37]

def attack( argc, argv ) :
  t, s, M, C, T = traces_ld( '../stage2.dat' )

  s, T = truncate_trace_samples(T, t, 0, 10000)
  s, T = compress_trace_samples(T, t, s, 20)

  print('\nGenerating PCC data for trace matrix')
  T_cpf, T_cpf_sqrt = get_col_pearson_factors_matrix(T, True)

  K = []
  for i in range(0, SIZE_OF_KEY):
    print('\nGenerating hyptohesis matrix for byte ' + str(i + 1) + '/16')
    h, H = generate_hypothesis_matrix( M, i, SIZE_OF_KEY, True )
    H_cpf, H_cpf_sqrt = get_col_pearson_factors_matrix(H)

    print('\nPerforming correlation analysis for byte ' + str(i + 1) + '/16')
    C, kb = disinguish_hypothesis( T, H, t, s, h, i, H_cpf, H_cpf_sqrt, T_cpf, T_cpf_sqrt, True )
    K.append(kb[0])

  print('\n\n' + str(K))


if ( __name__ == '__main__' ) :
  parser = argparse.ArgumentParser()
  parser.add_argument( '--debug',         dest = 'debug',                     action = 'store_true',                            default = False             )
  parser.add_argument( '--mode',          dest = 'mode',                      action = 'store', choices = [ 'uart', 'socket' ], default = 'uart'             )
  parser.add_argument( '--data',          dest = 'data',          type = str, action = 'store',                                 default = None               )
  parser.add_argument( '--uart',          dest = 'uart',          type = str, action = 'store',                                 default = '/dev/scale-board' )
  parser.add_argument( '--socket-host',   dest = 'socket_host',   type = str, action = 'store',                                 default = None               )
  parser.add_argument( '--socket-port',   dest = 'socket_port',   type = int, action = 'store',                                 default = None               )
  parser.add_argument( '--throttle-open', dest = 'throttle_open', type = int, action = 'store',                                 default = 1.0                )
  parser.add_argument( '--throttle-rd',   dest = 'throttle_rd',   type = int, action = 'store',                                 default = 0.1                )
  parser.add_argument( '--throttle-wr',   dest = 'throttle_wr',   type = int, action = 'store',                                 default = 0.1                )
  parser.add_argument( '--force-upper',   dest = 'force_upper',               action = 'store_true',                            default = False              )
  parser.add_argument( '--force-lower',   dest = 'force_lower',               action = 'store_true',                            default = False              )
  args = parser.parse_args()
  enc([0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 ])
  #attack( len( sys.argv ), sys.argv )
