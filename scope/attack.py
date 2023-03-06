# Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
# which can be found via http://creativecommons.org (and should be included as 
# LICENSE.txt within the associated archive or repository).

import  argparse, binascii, numpy, select, serial, socket, string, struct, sys, time


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

def board_rdln( fd    ) :
  r = ''

  while( True ):
    t = fd.read( 1 ).decode( 'ascii' )

    if ( args.debug ) :
      print( 'rdln> {0:s} [{1:02X}]'.format( t if ( t.isprintable() ) else ' ', ord( t ) ) )

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

  fd.write( ( x + '\x0D' ).encode( 'ascii' ) ) ; fd.flush()

  if ( args.debug ) :
    print( 'wrln> {0:s}'.format( x ) )

  time.sleep( args.throttle_wr )

## Client im ; x = args.data r = f_i( x )).

def enc(m) :
  fd = board_open()
  board_wrln( fd, "1")
  board_wrln( fd, m )
  r = board_rdln( fd )
  print(r)
  board_close( fd )

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



def truncate_trace_samples( T, t, start, end ):
  T_t = []
  for i in range(0, t):
    T_s = []
    for j in range(start, end):
      T_s.append(T[i][j])
    T_t.append(T_s)
  return T_t, end - start

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
  return T_t, int(s / n)

## Calculates the hamming weight of a given integer
## 
## \param[in] x the integer to process

def get_hamming_weight( x ):
  c = 0
  while x:
    c += 1
    x &= x - 1
  return c

## Generates a hyptohesis for each possible byte of the encyption key, given a list of messages
## 
## \param[in] M array of messages to use

def generate_hypothesis_matrix( M, b, track=False ):
  h = 256
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
    

def get_row_mean(R, i, s):
  mean = 0
  for j in range(0, s):
    mean += R[i][j]
  return mean / s

def get_col_mean(C, j, t):
  mean = 0
  for i in range(0, t):
    mean += C[i][j]
  return mean / t


def numpy_pearson_cor(x, y):
  xv = x -  numpy.mean(x,axis=0)
  yv = y -  numpy.mean(y,axis=0)
  xvss =  numpy.sum(xv * xv,axis=0)
  yvss =  numpy.sum(yv * yv,axis=0)
  result =  numpy.matmul( numpy.transpose(xv), yv) /  numpy.sqrt( numpy.outer(xvss, yvss))
  # bound the values to -1 to 1 in the event of precision issues
  return  numpy.maximum( numpy.minimum(result, 1.0), -1.0)


def get_col_pearson_factors(X):
  u = numpy.mean(X)
  X_norm = []
  X_norm_sqrt = 0
  for x in X:
    xn = x - u
    X_norm.append(xn)
    X_norm_sqrt += xn ** 2
  return X_norm, numpy.sqrt(X_norm_sqrt)

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

def get_correlation_at_point(H_cpf, H_cpf_sqrt, R_cpf, R_cpf_sqrt, i, j, t):
  HR = 0
  for x in range(0, t):
    HR += H_cpf[i][x] * R_cpf[j][x]
  return HR / ( H_cpf_sqrt[i] * R_cpf_sqrt[j])


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
      if corr > max[1]:
        max = (i, corr)
      if track:
        print_progress_bar(i*s + j, h*s, prefix='Progress', suffix='Complete', length=50)
    C.append(C_row)
  return max

## Attack implementation, as invoked from main after checking command line
## arguments.
##
## \param[in] argc number of command line arguments
## \param[in] argv           command line arguments

#s = 82560

def attack( argc, argv ) :
  t, s, M, C, T = traces_ld( '../stage2.dat' )

  T, s = truncate_trace_samples(T, t, 0, 20000)
  T, s = compress_trace_samples(T, t, s, 5)

  print('\nGenerating PCC data for trace matrix')
  T_cpf, T_cpf_sqrt = get_col_pearson_factors_matrix(T, True)

  K = []
  for i in range(0, 16):
    print('\nGenerating hyptohesis matrix for byte ' + str(i + 1) + '/16')
    h, H = generate_hypothesis_matrix( M, i, True )
    H_cpf, H_cpf_sqrt = get_col_pearson_factors_matrix(H)

    print('\nPerforming correlation analysis for byte ' + str(i + 1) + '/16')
    kb = disinguish_hypothesis( T, H, t, s, h, i, H_cpf, H_cpf_sqrt, T_cpf, T_cpf_sqrt, True )
    K.append(kb[0])
  print(K)


if ( __name__ == '__main__' ) :
  '''parser = argparse.ArgumentParser()
  parser.add_argument( '--debug',         dest = 'debug',                     action = 'store_true',                            default = True              )
  parser.add_argument( '--mode',          dest = 'mode',                      action = 'store', choices = [ 'uart', 'socket' ], default = 'uart'             )
  parser.add_argument( '--data',          dest = 'data',          type = str, action = 'store',                                 default = None               )
  parser.add_argument( '--uart',          dest = 'uart',          type = str, action = 'store',                                 default = '/dev/scale-board' )
  parser.add_argument( '--socket-host',   dest = 'socket_host',   type = str, action = 'store',                                 default = None               )
  parser.add_argument( '--socket-port',   dest = 'socket_port',   type = int, action = 'store',                                 default = None               )
  parser.add_argument( '--throttle-open', dest = 'throttle_open', type = int, action = 'store',                                 default = 1.0                )
  parser.add_argument( '--throttle-rd',   dest = 'throttle_rd',   type = int, action = 'store',                                 default = 0.5                )
  parser.add_argument( '--throttle-wr',   dest = 'throttle_wr',   type = int, action = 'store',                                 default = 0.5                )
  parser.add_argument( '--force-upper',   dest = 'force_upper',               action = 'store_true',                            default = False              )
  parser.add_argument( '--force-lower',   dest = 'force_lower',               action = 'store_true',                            default = False              )
  args = parser.parse_args()
  enc("1234567890123456")'''
  attack( len( sys.argv ), sys.argv )
