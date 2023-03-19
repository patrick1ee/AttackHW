/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#include "target.h" 

typedef uint8_t aes_gf28_t;
typedef uint16_t aes_poly_t;

//464.9us

/**
  * Pre-computed values for the x-time function: 
  * for a ∈ F 2 8 , computes a(x) · x (mod p(x)) (i.e., multiplies a by the indeterminate x).
  */
const aes_gf28_t XTIME[256] = {
  0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 
  0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E, 
  0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 
  0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E, 
  0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 
  0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E, 
  0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 
  0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E, 
  0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 
  0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E, 
  0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 
  0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE, 
  0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 
  0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE, 
  0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 
  0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE, 
  0x1B, 0x19, 0x1F, 0x1D, 0x13, 0x11, 0x17, 0x15, 
  0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05, 
  0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 
  0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25, 
  0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 
  0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45, 
  0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 
  0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65, 
  0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 
  0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85, 
  0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 
  0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5, 
  0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 
  0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5, 
  0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 
  0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5
};

/**
  * Pre-computed values for the AES S-box function
  */
const aes_gf28_t SBOX[265] = {
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
};

/**
  * Macro for the 'shift rows' step of AES
  */
#define AES_ENC_RND_ROW_STEP(a, b, c, d, e, f, g, h) { \
  aes_gf28_t __a1 = s[a];                              \
  aes_gf28_t __b1 = s[b];                              \
  aes_gf28_t __c1 = s[c];                              \
  aes_gf28_t __d1 = s[d];                              \
  s[e] = __a1;                                         \
  s[f] = __b1;                                         \
  s[g] = __c1;                                         \
  s[h] = __d1;                                         \
}

/**
  * Macro for the 'mix columns' step of AES
  */
#define AES_ENC_RND_MIX_STEP(a, b, c, d) { \
  aes_gf28_t __a1 = s[a];                  \
  aes_gf28_t __b1 = s[b];                  \
  aes_gf28_t __c1 = s[c];                  \
  aes_gf28_t __d1 = s[d];                  \
                                           \
  aes_gf28_t __a2 = XTIME[__a1];           \
  aes_gf28_t __b2 = XTIME[__b1];           \
  aes_gf28_t __c2 = XTIME[__c1];           \
  aes_gf28_t __d2 = XTIME[__d1];           \
                                           \
  aes_gf28_t __a3 = __a1 ^ __a2;           \
  aes_gf28_t __b3 = __b1 ^ __b2;           \
  aes_gf28_t __c3 = __c1 ^ __c2;           \
  aes_gf28_t __d3 = __d1 ^ __d2;           \
                                           \
  s[a] = __a2 ^ __b3 ^ __c1 ^ __d1;        \
  s[b] = __a1 ^ __b2 ^ __c3 ^ __d1;        \
  s[c] = __a1 ^ __b1 ^ __c2 ^ __d3;        \
  s[d] = __a3 ^ __b1 ^ __c1 ^ __d2;        \
}


/** Takes a current, i-th AES-128 round key matrix rk and a round constant rc as input, and operates on
  * it in-place to compute a next, (i + 1)-th AES-128 round key matrix as output.
  * \param[   out] rk (a pointer to) the current round key matrix
  * \param[   out] rc (a pointer to) the current round constant
  */
void aes_enc_exp_step( aes_gf28_t* rk, aes_gf28_t* rc ) {
  rk[0] = *rc ^ SBOX[rk[13]] ^ rk[0];
  rk[1] = SBOX[rk[14]] ^ rk[1];
  rk[2] = SBOX[rk[15]] ^ rk[2];
  rk[3] = SBOX[rk[12]] ^ rk[3];
  *rc = XTIME[*rc];
  for(int i = 4; i < 16; i++){
    rk[i] = rk[i - 4] ^ rk[i];
  }
}


/**
  * The round function Add-RoundKey which xors the current state matrix with the current round key matrix.
  * \param[   out]  s (a pointer to) the current state matrix
  * \param[in    ] rk (a pointer to) the current round key matrix
  */
void aes_enc_rnd_key( aes_gf28_t* s, aes_gf28_t* rk ) {
    for(int i = 0; i < 16; i++){
      s[i] = s[i] ^ rk[i];
    }
}

/**
  * The round function Substituion which makes use of the pre-computed S-BOX
  * \param[   out]  s (a pointer to) the current state matrix
  */
void aes_enc_rnd_sub( aes_gf28_t* s ) {
  for(int i = 0; i < 16; i++){
    s[i] = SBOX[s[i]];
  }
}

/**
  * The round function for Shift Rows
  * \param[   out]  s (a pointer to) the current state matrix
  */
void aes_enc_rnd_row( aes_gf28_t* s ) {
  AES_ENC_RND_ROW_STEP(1, 5, 9, 13, 13, 1, 5, 9);
  AES_ENC_RND_ROW_STEP(2, 6, 10, 14, 10, 14, 2, 6);
  AES_ENC_RND_ROW_STEP(3, 7, 11, 15, 7, 11, 15, 3);
}

/**
  * The round function for Mix Columns
  * \param[   out]  s (a pointer to) the current state matrix
  */
void aes_enc_rnd_mix( aes_gf28_t* s ) {
  for(int i = 0; i < 4; i++, s += 4){
    AES_ENC_RND_MIX_STEP(0, 1, 2, 3);
  }
}


/** Converts byte in integer form into a single little endian "octet string" 
  * 
  * \param[in    ] octet (a pointer to) the sequence of chars to write to
  * \param[in    ]  byte                the byte integer to convert
  */

void byte_to_octet ( char* octet, const uint8_t byte ) {
  int byte_a = byte / 16;
  int byte_b = byte - (byte_a * 16);

  if ( byte_a < 9 ) {
    octet[ 0 ] = byte_a + 48;
  }
  else {
    octet[ 0 ] = ( byte_a - 10 ) + 65;
  }

  if ( byte_b < 9 ) {
    octet[ 1 ] = byte_b + 48;
  }
  else {
    octet[ 1 ] = ( byte_b - 10 ) + 65;
  }
}

/** Converts a single little endian "octet string" into its integer representation
  * 
  * \param[in    ] octet (a pointer to) the sequence of chars to be read from
  * \param[in    ]  byte                the byte integer to write to
  * \return                             integer flag indicating whether conversion was successfull
  */

int octet_to_byte ( uint8_t* byte, const char* octet ) {

  int byte_a = octet[ 0 ];
  int byte_b = octet[ 1 ];

  if ( byte_a < 48 || ( byte_a > 57 && byte_a < 65) || byte_a > 50) {
    return -1;
  }

  if ( byte_b < 48 || ( byte_b > 57 && byte_b < 65) || byte_b > 50) {
    return -1;
  }

  if ( byte_a >= 65 ) {
    byte_a = ( byte_a - 65 ) + 10;
  }
  else {
    byte_a -= 48;
  }

  if ( byte_b >= 65 ) {
    byte_b = ( byte_b - 65 ) + 10;
  }
  else {
    byte_b -= 48;
  }

  *byte = ( byte_a * 16 ) + byte_b;
  return 0;
}


/** Read    a sequence of bytes from the UART, using a simple length-prefixed, 
  * little-endian hexadecimal "octet string" format.
  * 
  * \param[   out]   r (a pointer to) the                   byte  sequence    read
  * \param[in    ] n_r                the maximum number of bytes          to read
  * \return                           the         number of bytes          in r
  */

int octetstr_rd( uint8_t* r, int n_r ) {
  
  int n_x = 0;
  uint8_t prefix, byte;
  char octet[ 2 ];

  octet[ 0 ] = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
  octet[ 1 ] = scale_uart_rd(SCALE_UART_MODE_BLOCKING);

  char seperator = scale_uart_rd(SCALE_UART_MODE_BLOCKING);

  if( seperator != ':' || octet_to_byte ( prefix, octet ) != 0 ) {
    return -1;
  }

  while ( n_x < n_r && n_r <= prefix * 2)  {
    octet[ 0 ] = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
    octet[ 1 ] = scale_uart_rd(SCALE_UART_MODE_BLOCKING);

    if ( octet_to_byte ( byte, octet ) != 0 ) {
      break;
    }

    r[n_x] = byte;
    n_x += 1;
  }
  return n_x;
}

/** Write   a sequence of bytes to   the UART, using a simple length-prefixed, 
  * little-endian hexadecimal "octet string" format.
  * 
  * \param[in    ]   x (a pointer to) the                   byte  sequence to write
  * \param[in    ] n_x                the         number of bytes          in x
  */

void octetstr_wr( const uint8_t* x, int n_x ) {
  
  if( n_x > 255){
    return;
  }

  char octet[ 2 ];

  byte_to_octet ( octet, n_x );
  scale_uart_wr ( SCALE_UART_MODE_BLOCKING, octet[ 0 ] );
  scale_uart_wr ( SCALE_UART_MODE_BLOCKING, octet[ 1 ] );
  scale_uart_wr ( SCALE_UART_MODE_BLOCKING, ':' );

  for(int i = 0; i < n_x; i++){
    byte_to_octet ( octet, x[ i ] );
    scale_uart_wr ( SCALE_UART_MODE_BLOCKING, octet[ 0 ] );
    scale_uart_wr ( SCALE_UART_MODE_BLOCKING, octet[ 1 ] );
  }
  scale_uart_wr ( SCALE_UART_MODE_BLOCKING, '\n' );
  return ;
}

/** Initialise an AES-128 encryption, e.g., expand the cipher key k into round
  * keys, or perform randomised pre-computation in support of a countermeasure;
  * this can be left blank if no such initialisation is required, because the
  * same k and r will be passed as input to the encryption itself.
  * 
  * \param[in    ]   k (a pointer to) an   AES-128 cipher key
  * \param[in    ]   r (a pointer to) some         randomness
  */

void aes_init(                               const uint8_t* k, const uint8_t* r ) {
  return;
}

/** Perform    an AES-128 encryption of a plaintext m under a cipher key k, to
  * yield the corresponding ciphertext c.
  * 
  * \param[   out]   c (a pointer to) an   AES-128 ciphertext
  * \param[in    ]   m (a pointer to) an   AES-128 plaintext
  * \param[in    ]   k (a pointer to) an   AES-128 cipher key
  * \param[in    ]   r (a pointer to) some         randomness
  */

void aes     ( uint8_t* c, const uint8_t* m, const uint8_t* k, const uint8_t* r ) {
  int NR = 10;
  aes_gf28_t rk[SIZEOF_BLK], s[SIZEOF_BLK];
    
  aes_gf28_t rcp = 0x01;
  aes_gf28_t* rkp = rk;
  memcpy(s, m, SIZEOF_BLK);
  memcpy(rkp, k, SIZEOF_BLK);

  aes_enc_rnd_key(s, rkp);

  for(int i = 1; i < NR; i++){
    aes_enc_rnd_sub(s);
    aes_enc_rnd_row(s);
    aes_enc_rnd_mix(s);
    aes_enc_exp_step(rkp, &rcp);
    aes_enc_rnd_key(s, rkp);
  }

  aes_enc_rnd_sub(s);
  aes_enc_rnd_row(s);
  aes_enc_exp_step(rkp, &rcp);
  aes_enc_rnd_key(s, rkp);
  memcpy(c, s, SIZEOF_BLK);
}

/** Initialise the SCALE development board, then loop indefinitely.  Each loop
  * iteration reads a command then processes it:
  *
  * 1. If command is inspect, then
  *
  *    - write the SIZEOF_BLK parameter,
  *      i.e., number of bytes in an  AES-128 plaintext  m, or ciphertext c,
  *      to the UART, 
  *    - write the SIZEOF_KEY parameter,
  *      i.e., number of bytes in an  AES-128 cipher key k,
  *      to the UART, 
  *    - write the SIZEOF_RND parameter,
  *      i.e., number of bytes in the         randomness r.
  *      to the UART.
  *
  * 2. If command is encrypt, then
  *
  *    - read  an   AES-128 plaintext  m from the UART,
  *    - read  some         randomness r from the UART,
  *    - initalise the encryption,
  *    - set the trigger signal to 1,
  *    - execute   the encryption, producing the ciphertext 
  *
  *      c = AES-128.Enc( m, k )
  *
  *      using the hard-coded cipher key k plus randomness r if/when need be,
  *    - set the trigger signal to 0,
  *    - write an   AES-128 ciphertext c to   the UART.
  */

int main( int argc, char* argv[] ) {
  scale_conf_t scale_conf = {
    .clock_type        = SCALE_CLOCK_TYPE_EXT,
    .clock_freq_source = SCALE_CLOCK_FREQ_16MHZ,
    .clock_freq_target = SCALE_CLOCK_FREQ_16MHZ,

    .tsc               = false
  };

  if( !scale_init( &scale_conf ) ) {
    return -1;
  }

  uint8_t cmd[ 1 ], c[ SIZEOF_BLK ], m[ SIZEOF_BLK ], k[ SIZEOF_KEY ] = { 0x13, 0x0D, 0xDC, 0xD0, 0x7A, 0x3C, 0x82, 0x76, 0x2E, 0x52, 0x9D, 0x03, 0xC1, 0xB6, 0xAE, 0xD6 }, r[ SIZEOF_RND ];

  while( true ) {
    if( 1 != octetstr_rd( cmd, 1 ) ) {
      break;
    }
    switch( cmd[ 0 ] ) {
      case COMMAND_INSPECT : {
        uint8_t t = SIZEOF_BLK; 
                    octetstr_wr( &t, 1 ); 
                t = SIZEOF_KEY; 
                    octetstr_wr( &t, 1 ); 
                t = SIZEOF_RND; 
                    octetstr_wr( &t, 1 ); 

        break;
      }
      case COMMAND_ENCRYPT : {
        if( SIZEOF_BLK != octetstr_rd( m, SIZEOF_BLK ) ) {
          break;
        }
        if( SIZEOF_RND != octetstr_rd( r, SIZEOF_RND ) ) {
          break;
        }

        aes_init(       k, r );
        
        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  true );
        aes     ( c, m, k, r );
        scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );

        octetstr_wr( c, SIZEOF_BLK );
        break;
      }
      case COMMAND_TEST : {
        uint8_t k[ 16 ] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
        uint8_t m[ 16 ] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
                            0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
        uint8_t c[ 16 ] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
                            0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
        uint8_t t[ 16 ];

        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  true );
        aes(t, m, k, r);
        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  false );
  
        if( !memcmp( t, c, 16 * sizeof( uint8_t ) ) ) {
          uint8_t x[ 20 ] = "AES.Enc( k, m ) == c";
          octetstr_wr( x, 20 );
        }
        else{
          uint8_t x[ 20 ] = "AES.Enc( k, m ) != c";
          octetstr_wr( x, 20 );
        }
      }
      default : {
        break;
      }
    }
  }

  return 0;
}
