#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Crypto.h"

int main(int argc, char *argv[]) {
  unsigned char *testBuff = calloc(256, sizeof(unsigned char));
  unsigned char *outBuff = calloc(SHA256_OUTPUT_BYTES, sizeof(unsigned char));
  unsigned char *testVec = (unsigned char *)"Eik";

  if (sizeof(unsigned long) != 8) {
    fprintf(stderr, "WARNING - SHA256: unsigned long is %lu bytes instead of expected 8. The max input length is affected.\n", sizeof(unsigned long));
  }

  //memcpy(testBuff, testVec, strlen(testVec));
  //ErikSha256(testBuff, 0, outBuff);

  free(testBuff); testBuff = NULL;
  free(outBuff); outBuff = NULL;

  return 0;
}
