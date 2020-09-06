#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Crypto.h"

/* ChaCha20 Block Function - UNTESTED
*/
void ChaCha20Block(unsigned char *key, unsigned char *nonce, uint32_t blockCount, unsigned char *output) {
  int ind;
  uint32_t state[CHACHA_STATE_SIZE] = {0}, stateResult[CHACHA_STATE_SIZE] = {0};
  PrintChaCha20State(state);
  ChaChaInitBlockState(state, key, nonce, blockCount);
  ChaChaInitBlockState(stateResult, key, nonce, blockCount);
  for (ind = 0; ind < 10; ind++) {
    // Row Rounds
    ChaChaQuartRound(&state[0], &state[4], &state[8], &state[12]);
    ChaChaQuartRound(&state[1], &state[5], &state[9], &state[13]);
    ChaChaQuartRound(&state[2], &state[6], &state[10], &state[14]);
    ChaChaQuartRound(&state[3], &state[7], &state[11], &state[15]);
    // Column Rounds
    ChaChaQuartRound(&state[0], &state[5], &state[10], &state[15]);
    ChaChaQuartRound(&state[1], &state[6], &state[11], &state[12]);
    ChaChaQuartRound(&state[2], &state[7], &state[8], &state[13]);
    ChaChaQuartRound(&state[3], &state[4], &state[9], &state[14]);
  }

  for (ind = 0; ind < CHACHA_STATE_SIZE; ind++) {
    stateResult[ind] += state[ind];
  }
  PrintChaCha20State(stateResult);
}

/* ChaCha20 Init State Function
 */
void ChaChaInitBlockState(uint32_t *state, unsigned char *key, unsigned char *nonce, uint32_t blockCount) {
  int ind;
  // Constants
  state[0] = 0x61707865; state[1] = 0x33206463; state[2] = 0x79622d32; state[3] = 0x6b206574;
  // Key Vals
  for (ind = 0; ind < 8; ind++) {
    memcpy(&state[4+ind], (key+(4*ind)), sizeof(uint32_t));
  }
  // Block Counter
  state[12] = blockCount;
  // Nonce Vals
  for (ind = 0; ind < 3; ind++) {
    memcpy(&state[13+ind], (nonce+(4*ind)), sizeof(uint32_t));
  }
}

/* Quarter Round Function
 */
void ChaChaQuartRound(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
  *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
  *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
  *a += *b; *d ^= *a; *d = (*d << 8) | (*d >> 24);
  *c += *d; *b ^= *c; *b = (*b << 7) | (*b >> 25);
}

/* Print ChaCha20 State Function
*/
void PrintChaCha20State(uint32_t *state) {
  int i;
  fprintf(stderr, "*******************STATE*******************\n");
  for (i = 0; i < 16; i++) {
    fprintf(stderr, "0x%08x ", state[i]);
    if (!((i+1) % 4)) fprintf(stderr, "\n");
  }
}
