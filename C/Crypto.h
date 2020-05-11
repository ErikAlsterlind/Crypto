#ifndef __CRYPTO__
#define __CRYPTO__

enum algorithm {
  SHA256 = 1,
};

// SHA256
#define SHA256_OUTPUT_BITS    256
#define SHA256_OUTPUT_BYTES   (SHA256_OUTPUT_BITS / 8)
#define SHA256_BLOCK_SIZE     512
#define SHA256_PAD_ZEROES_VAL   448

#define ERR_ALLOC             -1
#define ERR_SHA256_PADDING    -2

void ErikSha256(unsigned char *inBuff, unsigned long inLenBits, unsigned char *outBuff);
int PadInputSha256(unsigned char **inBuff, unsigned long *inLenBitsPtr);
unsigned int CalcPadBitLenSha256(unsigned long currLen);
unsigned int CalcNumPadZeroesSha256(unsigned long currLen);
void DumpHexString(unsigned char *input, unsigned long inLenBits);

#endif