#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Crypto.h"

/* Function for printing string as a hex string
 */
void PrintBinAsHex(unsigned char *input) {
  unsigned int ind;
  unsigned int len = strlen((const char *)input);

  for (ind = 0; ind < len; ind++) {
    fprintf(stderr, "%02X ", input[ind]);
    if (!((ind+1) % 16)) {
      fprintf(stderr, "\n");
    }
  }
}

/*  ChaCha20 encryption function - TESTING
 */
int ErikChaCha20Encrypt(unsigned char *input, unsigned char *key, unsigned char *nonce, uint32_t counter, unsigned char *output) {
  unsigned int inputLen = 0, totalBlocks = 0;
  unsigned int ind = 0, innerInd = 0;
  unsigned char keyStream[65] = {0};
  unsigned char *tempOutput;

  if (!(input) || !(key) || !(nonce) || !(output)) {
    fprintf(stderr, "ERROR - CHACHA20: invalid input to top level function.\n");
    return ERR_CHACHA_MAIN;
  }
  
  /*fprintf(stderr, "input: %s\n", input);
  fprintf(stderr, "key: %s\n", key);
  fprintf(stderr, "nonce: %s\n", nonce);
  fprintf(stderr, "counter: %d\n", counter);
  */
  inputLen = strlen((const char *)input);
  totalBlocks = (inputLen / 64) + (!(inputLen % 64) ? 0 : 1);
  //fprintf(stderr, "Total Blocks: %d\n", totalBlocks);
  if (!(tempOutput = calloc((totalBlocks*64)+1, sizeof(unsigned char *)))) {
    fprintf(stderr, "ERROR - CHACHA20: calloc failed to allocate a buffer.\n");
    return ERR_ALLOC;
  }
  memcpy(tempOutput, input, inputLen);

  for (ind = 0; ind < totalBlocks; ind++) {
    ChaCha20Block(key, nonce, counter+ind, keyStream);
    /*fprintf(stderr, "Keystream %d:\n", ind);
    PrintBinAsHex(keyStream);
    fprintf(stderr, "\n");
    */
    for (innerInd = 0; innerInd < 64; innerInd++) {
      tempOutput[(64*ind)+innerInd] ^= keyStream[innerInd];
    }
    memset(keyStream, 0, 64);
  }
  memcpy(output, tempOutput, inputLen);
  //PrintBinAsHex(output);

  return 0;
}

/* ChaCha20 Block Function
*/
void ChaCha20Block(unsigned char *key, unsigned char *nonce, uint32_t blockCount, unsigned char *output) {
  int ind;
  uint32_t state[CHACHA_STATE_SIZE] = {0}, stateResult[CHACHA_STATE_SIZE] = {0};
  if (!output) {
    fprintf(stderr, "ERROR: output buffer passed to ChaCha20 Block function is NULL! The function will not be performed.\n");
    return;
  }
  ChaChaInitBlockState(state, key, nonce, blockCount);
  //PrintChaCha20State(state);
  ChaChaInitBlockState(stateResult, key, nonce, blockCount);
  for (ind = 0; ind < 10; ind++) {
    // Column Rounds
    ChaChaQuartRound(&state[0], &state[4], &state[8], &state[12]);
    ChaChaQuartRound(&state[1], &state[5], &state[9], &state[13]);
    ChaChaQuartRound(&state[2], &state[6], &state[10], &state[14]);
    ChaChaQuartRound(&state[3], &state[7], &state[11], &state[15]);
    // Diagonal Rounds
    ChaChaQuartRound(&state[0], &state[5], &state[10], &state[15]);
    ChaChaQuartRound(&state[1], &state[6], &state[11], &state[12]);
    ChaChaQuartRound(&state[2], &state[7], &state[8], &state[13]);
    ChaChaQuartRound(&state[3], &state[4], &state[9], &state[14]);
  }
  for (ind = 0; ind < CHACHA_STATE_SIZE; ind++) {
    stateResult[ind] += state[ind];
    memcpy(output+(ind*4), &stateResult[ind], sizeof(uint32_t));
  }
  //PrintChaCha20State(stateResult);
}

/* ChaCha20 Init State Function
 */
void ChaChaInitBlockState(uint32_t *state, unsigned char *key, unsigned char *nonce, uint32_t blockCount) {
  int ind;
  // Constants
  state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
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
  //PrintChaCha20State(state);
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