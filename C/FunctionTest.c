#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "Crypto.h"

// Pick an arbitrary max vector length for read in test vectors
#define MAX_VECTOR_BYTE_LEN   2048

// Function that prints a uniform error message for Sha256 errors
void PrintRegressErrorSha256(void) {
  fprintf(stderr, "ERROR - SHA256: invalid test vector file provided to regression.\n"); 
  fprintf(stderr, "The file must contain pairs of lines where the first line is an input string within double quotes");
  fprintf(stderr, "and the second line is a hex string that is exactly 64 characters long.\n");
}

// Function that prints a result for a given regression test
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

// Regression test top level function for sha256
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
    // Get rid of newline on input line when copying
    line[dataRead-1] = 0x0;
    dataRead--;

    // Make sure input line is within double quotes
    if ((line[0] != '"') || (line[dataRead-1] != '"')) {
      PrintRegressErrorSha256();
      free(output); output = NULL;
      break;
    }
    // Adjust length to ignore quotes
    dataRead -= 2;

    inLenBits = dataRead * 8;
    input = calloc(dataRead + 1, sizeof(unsigned char));
    memcpy(input, line+1, dataRead);

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

// Simple help menu for a user
void PrintHelp(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, " -s <filename>: run sha256 regression\n");
  fprintf(stderr, " -h: print help menu\n");
}

// Main function
int main(int argc, char *argv[]) {
  int c;
  FILE *testFile;
  unsigned int inLenBits = 0;
  unsigned int sha256RegressFlag = 0;
  unsigned int sha256GenFlag = 0;
  unsigned char *sha256File;
  unsigned char *inputStr;
  unsigned char outputsha256[SHA256_OUTPUT_BYTES+1] = {0};

  if (sizeof(unsigned long) != 8) {
    fprintf(stderr, "WARNING - SHA256: unsigned long is %lu bytes instead of expected 8. The max input length is affected.\n", sizeof(unsigned long));
  }

  while ((c = getopt (argc, argv, "s:g:h")) != -1) {
    switch (c)
      {
      case 's':
        sha256RegressFlag = 1;
        sha256File = (unsigned char *)optarg;
        break;
      case 'g':
        sha256GenFlag = 1;
        if (!(inputStr = calloc(strlen(optarg), sizeof(unsigned char)))) {
          fprintf(stderr, "WARNING - SHA256: unable to generate buffer for sha256 generate case.\n");
          return 1;
        }
        memcpy(inputStr, optarg, strlen(optarg));
        break;
      case 'h':
        PrintHelp();
        break;
      default:
        PrintHelp();
    }
  }

  if (sha256RegressFlag) {
    if (!(testFile = fopen((const char *)sha256File, "r"))) {
      fprintf(stderr, "ERROR - SHA256: Unable to open provided test vector file %s.\n", sha256File);
      return 1;
    }
    RegressionSha256(testFile);
    fclose(testFile);
  }

  if (sha256GenFlag) {
    inLenBits = strlen((const char *)inputStr) * 8;
    ErikSha256(inputStr, inLenBits, outputsha256);
    //DumpHexString((unsigned char *)outputsha256, SHA256_OUTPUT_BITS);
    free(inputStr);
  }

  return 0;
}