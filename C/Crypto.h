#ifndef __CRYPTO__
#define __CRYPTO__

enum algorithm {
  SHA256 = 1,
  CHACHA20,
};

// SHA256
#define SHA256_OUTPUT_BITS        256
#define SHA256_OUTPUT_BYTES       (SHA256_OUTPUT_BITS / 8)
#define SHA256_BLOCK_SIZE_BITS    512
#define SHA256_BLOCK_SIZE_BYTES   (SHA256_BLOCK_SIZE_BITS / 8)
#define SHA256_PAD_ZEROES_VAL     448

#define SHA256_RR(val, shift)     ((val >> shift) | (val << (32 - shift)))
#define SHA256_SR(val, shift)     (val >> shift)
#define SHA256_CH_FUNC(e, f, g)   ((e & f) ^ ((~e) & g))
#define SHA256_MAJ_FUNC(a, b, c)  ((a & b) ^ (a & c) ^ (b & c))
#define SHA256_BSIGMA0_FUNC(x)    ((SHA256_RR(x, 2)) ^ (SHA256_RR(x, 13)) ^ (SHA256_RR(x, 22)))
#define SHA256_BSIGMA1_FUNC(x)    ((SHA256_RR(x, 6)) ^ (SHA256_RR(x, 11)) ^ (SHA256_RR(x, 25)))
#define SHA256_LSIGMA0_FUNC(x)    ((SHA256_RR(x, 7)) ^ (SHA256_RR(x, 18)) ^ (SHA256_SR(x, 3)))
#define SHA256_LSIGMA1_FUNC(x)    ((SHA256_RR(x, 17)) ^ (SHA256_RR(x, 19)) ^ (SHA256_SR(x, 10)))

#define ERR_ALLOC                 -1
#define ERR_SHA256_PADDING        -2
#define ERR_SHA256_MESS_SCHED     -3
#define ERR_SHA256_COMPRESS       -4
#define ERR_SHA256_BIGENDCONV     -5
#define ERR_SHA256_MAIN           -6

int ErikSha256(unsigned char *inBuff, unsigned long inLenBits, unsigned char *outBuff);
void CompressFuncSha256(unsigned int workingVars[8], unsigned int messageSchedule[64]);
int GenMessageScheduleSha256(unsigned char *inputBlock, unsigned int messageSchedule[64]);
int PadInputSha256(unsigned char **inBuff, unsigned long *inLenBitsPtr);
unsigned int CalcPadBitLenSha256(unsigned long currLen);
unsigned int CalcNumPadZeroesSha256(unsigned long currLen);
void DumpHexString(unsigned char *input, unsigned long inLenBits);
void DumpHexStringBytes(unsigned char *input, unsigned long inLenBits);
int EndiannessConvertWordSha256(unsigned char *buff, unsigned long numBits);

// ChaCha20
#define CHACHA_KEY_SIZE_BITS      256
#define CHACHA_KEY_SIZE_BYTES     (CHACHA20_KEYSIZE_BITS / 8)
#define CHACHA_NONCE_SIZE_BITS    96
#define CHACHA_NONCE_SIZE_BYTES   (CHACHA20_NONCESIZE_BITS / 8)
#define CHACHA_STATE_SIZE         16

void ChaCha20Block(unsigned char *key, unsigned char *nonce, uint32_t blockCount, unsigned char *output);
void ChaChaInitBlockState(uint32_t *state, unsigned char *key, unsigned char *nonce, uint32_t blockCount);
void ChaChaQuartRound(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);
void PrintChaCha20State(uint32_t *state);

#endif