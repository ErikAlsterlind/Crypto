#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Crypto.h"

static unsigned int initHashSha256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
static unsigned int constantWordsSha256[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
                                            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
                                            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
                                            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
                                            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
                                            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
                                            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
                                            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
                                            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// Top level sha256 function assumes inBuff is validly allocated and outBuff is a 32B allocated array
void ErikSha256(unsigned char *inBuff, unsigned long inLenBits, unsigned char *outBuff) {
    unsigned long currInputLenBits = inLenBits;
    unsigned long numBlocks;
    unsigned int index, innerIndex;
    unsigned int currHash[8] = {0}, workingVars[8] = {0};
    unsigned int messageSchedule[64] = {0};

    if (!outBuff) {
        fprintf(stderr, "ERROR - SHA256: invalid output buffer provided to function. Must be %d bytes.\n", SHA256_OUTPUT_BYTES);
        return;
    }
    DumpHexString(inBuff, currInputLenBits);
    if (PadInputSha256(&inBuff, &currInputLenBits)) {
        fprintf(stderr, "SHA256 function not completed. Returning...\n");
        return;
    }
    DumpHexStringBytes(inBuff, currInputLenBits);
    //DumpHexString(inBuff, currInputLenBits);

    numBlocks = currInputLenBits / SHA256_BLOCK_SIZE_BITS;
    memcpy(currHash, initHashSha256, sizeof(unsigned int)*8);

    for (index = 0; index < numBlocks; index++) { 
        memcpy(workingVars, currHash, sizeof(unsigned int)*8);
        GenMessageScheduleSha256((inBuff+(index*SHA256_BLOCK_SIZE_BYTES)), messageSchedule);
        CompressFuncSha256(workingVars, messageSchedule);
        for (innerIndex = 0; innerIndex < 8; innerIndex++) {
            currHash[innerIndex] = currHash[innerIndex] + workingVars[innerIndex];
        }
    }

    for (index = 0; index < 8; index++) {
        memcpy(outBuff+(index*8), &currHash[index], sizeof(unsigned int));
    }
}

void CompressFuncSha256(unsigned int workingVars[8], unsigned int messageSchedule[64]) {
    unsigned int index, innerIndex;
    unsigned int T1 = 0, T2 = 0;
    unsigned int *a = &workingVars[0];
    unsigned int *b = &workingVars[1];
    unsigned int *c = &workingVars[2];
    unsigned int *d = &workingVars[3];
    unsigned int *e = &workingVars[4];
    unsigned int *f = &workingVars[5];
    unsigned int *g = &workingVars[6];
    unsigned int *h = &workingVars[7];

    for (index = 0; index < 64; index++) {
        if (index < 2) {
            for (innerIndex = 0; innerIndex < 8; innerIndex++) {
                fprintf(stderr, "%08X ", workingVars[innerIndex]);
            }
            fprintf(stderr, "\n");
        }
        T1 = (*h) + (SHA256_BSIGMA1_FUNC((*e))) + (SHA256_CH_FUNC((*e), (*f), (*g))) 
                + constantWordsSha256[index] + messageSchedule[index];
        T2 = (SHA256_BSIGMA0_FUNC((*a))) + (SHA256_MAJ_FUNC((*a), (*b), (*c)));
        *h = *g;
        *g = *f;
        *f = *e;
        *e = (*d) + T1;
        *d = *c;
        *c = *b;
        *b = *a;
        *a = T1 + T2;
    }
}

int GenMessageScheduleSha256(unsigned char *inputBlock, unsigned int messageSchedule[64]) {
    unsigned int index, offset;

    if (!inputBlock) {
        fprintf(stderr, "ERROR - SHA256: NULL pointer passed as input block to generate message schedule.\n");
        return ERR_SHA256_MESS_SCHED;
    }
    for (index = 0; index < 16; index++) {
        memcpy(&(messageSchedule[index]), inputBlock+(sizeof(unsigned int)*index), sizeof(unsigned int));
    }
    for (; index < 64; index++) {
        // Using the 32b overflow like a mod 2^32 operation works I think
        messageSchedule[index] = ((SHA256_LSIGMA1_FUNC(messageSchedule[index-2])) + messageSchedule[index-7] 
                                    + (SHA256_LSIGMA0_FUNC(messageSchedule[index-15])) + messageSchedule[index-16]);
    }

    return 0;
}

// Implicit length limit of 2^32 thanks to unsigned int type
int PadInputSha256(unsigned char **inBuff, unsigned long *inLenBitsPtr) {
    unsigned char *oldInput;
    unsigned char *input = (*inBuff);
    unsigned long newLenBits = 0;
    unsigned long inLenBits = (*inLenBitsPtr);
    unsigned long inLenBytes = ((*inLenBitsPtr) / 8) + (((*inLenBitsPtr) % 8) ? 1 : 0);
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
    unsigned int modulus = SHA256_BLOCK_SIZE_BITS;
    unsigned int totalOnes = 0;

    // Add value for initial padding 1 bit
    currLen++;
    currLen %= modulus;
    if (currLen < SHA256_PAD_ZEROES_VAL) {
        totalOnes = (SHA256_PAD_ZEROES_VAL - currLen);
    } else if (currLen > SHA256_PAD_ZEROES_VAL) {
        totalOnes = SHA256_BLOCK_SIZE_BITS - currLen;
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

void DumpHexStringBytes(unsigned char *input, unsigned long inLenBits) {
    unsigned int index;
    unsigned long loopLim = (inLenBits / 8) + ((inLenBits % 8) ? 1 : 0);

    if (((inLenBits < 32) && inLenBits) || (inLenBits % 8)) loopLim++;
    fprintf(stderr, "Dumping %lu bit input in %lu hex bytes.\n", inLenBits, loopLim);
    for (index = 0; index < loopLim; index++) {
        fprintf(stderr, "%02X ", input[index]);
        if (!((index+1) % 32)) {
            fprintf(stderr, "\n");
        }
    }
}