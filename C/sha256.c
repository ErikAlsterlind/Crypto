#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Crypto.h"

static unsigned int initHash[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// Top level sha256 function assumes inBuff is validly allocated and outBuff is a 32B allocated array
void ErikSha256(unsigned char *inBuff, unsigned long inLenBits, unsigned char *outBuff) {
    unsigned long currInputLenBits = inLenBits;
    if (!outBuff) {
        fprintf(stderr, "ERROR - SHA256: invalid output buffer provided to function. Must be %d bytes.\n", SHA256_OUTPUT_BYTES);
        return;
    }
    if (PadInputSha256(&inBuff, &currInputLenBits)) {
        fprintf(stderr, "SHA256 function not completed. Returning...\n");
        return;
    }
}

// Implicit length limit of 2^32 thanks to unsigned int type
int PadInputSha256(unsigned char **inBuff, unsigned long *inLenBitsPtr) {
    unsigned char *oldInput;
    unsigned char *input = (*inBuff);
    unsigned long newLenBits = 0;
    unsigned long inLenBits = (*inLenBitsPtr);
    unsigned long inLenBytes = (*inLenBitsPtr) / 8;
    unsigned long numZeroes = CalcNumPadZeroesSha256(inLenBits);
    unsigned char inLenStr[8] = {0};

    if (!input && (inLenBits != 0)) {
        fprintf(stderr, "ERROR - SHA256: input padding passed NULL buffer with a non zero length %lu.\n", inLenBits);
        return ERR_SHA256_PADDING;
    }

    memcpy(inLenStr, &inLenBits, sizeof(unsigned long));
    if (inLenBits) {
        oldInput = calloc(inLenBytes, sizeof(unsigned char));
        memcpy(oldInput, input, inLenBytes);
        free(input); input = NULL;
    }

    input = (*inBuff) = calloc(CalcPadBitLenSha256(inLenBits) / 8, sizeof(unsigned char));
    if (!input) {
        fprintf(stderr, "ERROR - SHA256: unable to allocate memory in PadInputSha256.\n");
        free(oldInput);
        return ERR_ALLOC;
    }

    if (inLenBits) {
        memcpy(input, oldInput, inLenBytes);
        free(oldInput); oldInput = NULL;
    }
    newLenBits = inLenBits;
    input[(newLenBits / 8)] |= (1 << (newLenBits % 8));
    newLenBits = newLenBits + 1 + numZeroes;
    memcpy(input+(newLenBits/8), inLenStr, 8);
    newLenBits += 64;
    
    (*inLenBitsPtr) = newLenBits;
    return 0;
}
unsigned int CalcPadBitLenSha256(unsigned long currLen) {
    unsigned int numZeroes = CalcNumPadZeroesSha256(currLen);
    currLen = currLen + 1 + numZeroes + 64;
    return currLen;
}
unsigned int CalcNumPadZeroesSha256(unsigned long currLen) {
    unsigned int modulus = SHA256_BLOCK_SIZE;
    unsigned int totalOnes = 0;

    // Add value for initial padding 1 bit
    currLen++;
    currLen %= modulus;
    if (currLen < SHA256_PAD_ZEROES_VAL) {
        totalOnes = (SHA256_PAD_ZEROES_VAL - currLen);
    } else if (currLen > SHA256_PAD_ZEROES_VAL) {
        totalOnes = SHA256_BLOCK_SIZE - currLen;
        totalOnes += SHA256_PAD_ZEROES_VAL;
    }

    return totalOnes;
}
void DumpHexString(unsigned char *input, unsigned long inLenBits) {
    unsigned int index;
    unsigned int loopLim = (inLenBits / (sizeof(unsigned int)*8));
    unsigned int printVal = 0;

    if (((inLenBits < 32) && inLenBits) || (inLenBits % 8)) loopLim++;
    fprintf(stderr, "Dumping %lu bit input in 32b hex words.\n", inLenBits);
    for (index = 0; index < loopLim; index++) {
        memcpy(&printVal, (input+(index*4)), sizeof(unsigned int));
        fprintf(stderr, "%d: 0x%08X\n", index, printVal);
    }
}