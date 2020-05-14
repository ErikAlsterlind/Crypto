#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "Crypto.h"

#define MAX_VECTOR_BYTE_LEN   2048

void PrintRegressErrorSha256(void) {
  fprintf(stderr, "ERROR - SHA256: invalid test vector file provided to regression.\n"); 
  fprintf(stderr, "The file must contain pairs of lines where the first line is an input string");
  fprintf(stderr, "and the second line is a hex string that is exactly 64 characters long.\n");
}

int PrintRegressResult(unsigned char *input, unsigned char *output, unsigned char *expected) {
  unsigned int expectedSize = strlen((const char *)expected);
  unsigned int result = 0, index;
  unsigned char outputHex[65] = {0};
  int ret = 0;

  fprintf(stderr, "Input: %s\n", input);
  fprintf(stderr, "Result: ");
  if (expectedSize != SHA256_OUTPUT_BYTES*2) {
    fprintf(stderr, "FAILURE\nProvided expected output is an invalid size. Expecting 64 hex digits, found %d\n", expectedSize);
    return 1;
  }

  // Converting real output to hex digits to compare to expected
  BigEndianConvertSha256(output, SHA256_OUTPUT_BITS);
  for (index = 0; index < SHA256_OUTPUT_BYTES; index++) {
    sprintf((char *)(outputHex + (2*index)), "%02x", output[index]);
  }

  result = memcmp(outputHex, expected, expectedSize);
  if (!result) {
    fprintf(stderr, "SUCCESS\n\n");
  } else {
    fprintf(stderr, "FAILURE\nFunction output: %s\n", outputHex);
    fprintf(stderr, "Expected output: %s\n\n", expected);
    ret = 1;
  }

  return ret;
}

void RegressionSha256(FILE *testVecFile) {
  unsigned char line[(MAX_VECTOR_BYTE_LEN+1)], *input, *output, *targetOutput;
  unsigned int dataRead = 0;
  unsigned long inLenBits;
  int totalFailures = 0, totalTests = 0;
  
  if (!(output = calloc(SHA256_OUTPUT_BYTES+1, sizeof(unsigned char)))) {
    fprintf(stderr, "ERROR - SHA256 Regression: failed to allocate memory for output buffer. Regression will not run.\n");
    return;
  }
  fprintf(stderr, "--- SHA256 Regression Test ---\n");
  while (fgets((char *)line, MAX_VECTOR_BYTE_LEN, testVecFile) != NULL) {
    dataRead = strlen((const char *)line);
    if (dataRead == 1) {
      continue;
    } else if (line[dataRead-1] != '\n') {
      PrintRegressErrorSha256();
      free(output); output = NULL;
      break;
    }
    line[dataRead-1] = 0x0;
    dataRead--;

    inLenBits = dataRead * 8;
    input = calloc(dataRead + 1, sizeof(unsigned char));
    memcpy(input, line, dataRead);

    if(!fgets((char *)line, MAX_VECTOR_BYTE_LEN, testVecFile)) {
      PrintRegressErrorSha256();
      free(input); input = NULL;
      free(output); output = NULL;
      break;
    }

    dataRead = strlen((const char *)line);
    if (line[dataRead-1] == '\n') {
      line[dataRead-1] = 0x0;
      dataRead--;
    }

    targetOutput = calloc(dataRead + 1, sizeof(unsigned char));
    memcpy(targetOutput, line, dataRead);
    if (!ErikSha256(input, inLenBits, output)) {
      totalFailures += PrintRegressResult(input, output, targetOutput);
    }
    totalTests++;
    free(input); input = NULL;
    free(targetOutput); targetOutput = NULL;
  }
  fprintf(stderr, "--- Total Tests: %d ---\n", totalTests);
  fprintf(stderr, "--- Total Successes: %d ---\n", totalTests - totalFailures);
  fprintf(stderr, "--- Total Failures: %d ---\n", totalFailures);

  free(output); output = NULL;
}

void PrintHelp(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, " -s <filename>: run sha256 regression\n");
  fprintf(stderr, " -h: print help menu\n");
}

int main(int argc, char *argv[]) {
  int c;
  FILE *testFile;
  unsigned int sha256Flag = 0;
  unsigned char *sha256File;
  unsigned char outBuff[SHA256_OUTPUT_BYTES];

  if (sizeof(unsigned long) != 8) {
    fprintf(stderr, "WARNING - SHA256: unsigned long is %lu bytes instead of expected 8. The max input length is affected.\n", sizeof(unsigned long));
  }

  while ((c = getopt (argc, argv, "s:h")) != -1) {
    switch (c)
      {
      case 's':
        sha256Flag = 1;
        sha256File = (unsigned char *)optarg;
        break;
      case 'h':
        PrintHelp();
        break;
      default:
        PrintHelp();
    }
  }

  if (sha256Flag) {
    if (!(testFile = fopen((const char *)sha256File, "r"))) {
      fprintf(stderr, "ERROR - SHA256: Unable to open provided test vector file %s.\n", sha256File);
      return 1;
    }
    RegressionSha256(testFile);
    fclose(testFile);
  }

  return 0;
}