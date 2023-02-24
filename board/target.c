/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#include "target.h" 

typedef uint8_t aes_gf28_t;
typedef uint16_t aes_poly_t;

/* For a ∈ F 2 8 , computes a(x) · x (mod p(x)) (i.e., multiplies a by the indeterminate x). */
aes_gf28_t xtime( aes_gf28_t a ) {
    if((a & 0x80) == 0x80) {
        //Performs reduction if leading bit = 1
        return 0x1B ^ (a << 1);
    }
    else {
        return a << 1;
    }
}

/* For a, b ∈ F 2 8 , computes a(x) · b(x) (mod p(x)) (i.e., multiplies a by b). */
aes_gf28_t btime( aes_gf28_t a, aes_gf28_t b ) {
  aes_gf28_t t = 0;
  for(int i = 7; i >= 0; i--){
    t = xtime(t);
    if((b >> i) & 1){
      t ^= a;
    }
  }
  return t;
}

/* Inverts a ∈ F 2 8 , by raising a to the power of 2^8 - 2 (Fermats little theorem) */
aes_gf28_t aes_gf28_inv( aes_gf28_t a ) {
  aes_gf28_t t_0 = btime(a, a);       // a^2
  aes_gf28_t t_1 = btime(t_0, a);     // a^3
  t_0 = btime(t_0, t_0);              // a^4
  t_1 = btime(t_1, t_0);              // a^7
  t_0 = btime(t_0, t_0);              // a^8
  t_0 = btime(t_1, t_0);              // a^15
  t_0 = btime(t_0, t_0);              // a^30
  t_0 = btime(t_0, t_0);              // a^60
  t_1 = btime(t_1, t_0);              // a^67
  t_0 = btime(t_0, t_1);              // a^127
  t_0 = btime(t_0, t_0);              // a^254 (a^(2^8))
  return t_0;
}

/* For a ∈ F 2 8 , computes S-box(a) (i.e., applies the AES S-box to a). */
aes_gf28_t sbox( aes_gf28_t a ) {
  a = aes_gf28_inv(a);
  a = (0x63)   //   0   1   1   0   0   0   1   1
   ^  (a)      // a_7 a_6 a_5 a_4 a_3 a_2 a_1 a_0
   ^ (a << 1)  // a_6 a_5 a_4 a_3 a_2 a_1 a_0   0
   ^ (a << 2)  // a_5 a_4 a_3 a_2 a_1 a_0   0   0
   ^ (a << 3)  // a_4 a_3 a_2 a_1 a_0   0   0   0
   ^ (a << 4)  // a_3 a_2 a_1 a_0   0   0   0   0
   ^ (a >> 7)  //   0   0   0   0   0   0   0 a_7
   ^ (a >> 6)  //   0   0   0   0   0   0 a_7 a_6
   ^ (a >> 5)  //   0   0   0   0   0 a_7 a_6 a_5
   ^ (a >> 4); //   0   0   0   0 a_7 a_6 a_5 a_4
  return a;
}

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

#define AES_ENC_RND_MIX_STEP(a, b, c, d) { \
  aes_gf28_t __a1 = s[a];                  \
  aes_gf28_t __b1 = s[b];                  \
  aes_gf28_t __c1 = s[c];                  \
  aes_gf28_t __d1 = s[d];                  \
                                           \
  aes_gf28_t __a2 = xtime(__a1);           \
  aes_gf28_t __b2 = xtime(__b1);           \
  aes_gf28_t __c2 = xtime(__c1);           \
  aes_gf28_t __d2 = xtime(__d1);           \
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
  */
void aes_enc_exp_step( aes_gf28_t* rk, aes_gf28_t* rc ) {
  rk[0] = *rc ^ sbox(rk[13]) ^ rk[0];
  rk[1] = sbox(rk[14]) ^ rk[1];
  rk[2] = sbox(rk[15]) ^ rk[2];
  rk[3] = sbox(rk[12]) ^ rk[3];
  *rc = xtime(*rc);
  for(int i = 4; i < 16; i++){
    rk[i] = rk[i - 4] ^ rk[i];
  }
}


/* The round function Add-RoundKey */
void aes_enc_rnd_key( aes_gf28_t* s, aes_gf28_t* rk ) {
    for(int i = 0; i < 16; i++){
      s[i] = s[i] ^ rk[i];
    }
}

void aes_enc_rnd_sub( aes_gf28_t* s ) {
  for(int i = 0; i < 16; i++){
    s[i] = sbox(s[i]);
  }
}

/* The round function Shift-Rows for encryption */
void aes_enc_rnd_row( aes_gf28_t* s ) {
  AES_ENC_RND_ROW_STEP(1, 5, 9, 13, 13, 1, 5, 9);
  AES_ENC_RND_ROW_STEP(2, 6, 10, 14, 10, 14, 2, 6);
  AES_ENC_RND_ROW_STEP(3, 7, 11, 15, 7, 11, 15, 3);
}

/* The round function Mix-Columns for encryption */
void aes_enc_rnd_mix( aes_gf28_t* s ) {
  for(int i = 0; i < 4; i++, s += 4){
    AES_ENC_RND_MIX_STEP(0, 1, 2, 3);
  }
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
  while(n_x < n_r){
    uint8_t c = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
    if(c == '\r' || c == '\n'){
      break;
    }
    r[n_x] = c;
    n_x += 1;
  }
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, '\n');
  return n_x;
}

/** Write   a sequence of bytes to   the UART, using a simple length-prefixed, 
  * little-endian hexadecimal "octet string" format.
  * 
  * \param[in    ]   x (a pointer to) the                   byte  sequence to write
  * \param[in    ] n_x                the         number of bytes          in x
  */

void octetstr_wr( const uint8_t* x, int n_x ) {
  for(int i = 0; i < n_x; i++){
    scale_uart_wr(SCALE_UART_MODE_BLOCKING, x[i]);
  }
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, '\n');
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
        
        //truct timeval stop, start;

        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  true );
        //gettimeofday(&start, NULL);
        aes     ( c, m, k, r );
        //gettimeofday(&stop, NULL);
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
