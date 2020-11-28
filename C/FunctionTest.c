#include <ctype.h>
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
  fprintf(stderr, "The file must contain pairs of lines where the first line is an input string within double quotes\n");
  fprintf(stderr, "and the second line is a hex string output that is exactly 64 characters long.\n");
}

// Function that prints a uniform error message for ChaCha20 errors
void PrintRegressErrorChaCha20(void) {
  fprintf(stderr, "ERROR - ChaCha20: invalid test vector file provided to regression.\n"); 
  fprintf(stderr, "The file must contain a set of five lines where the first line is either an input ascii string within double quotes or\n"); 
  fprintf(stderr, "an input hex string, the second line is a hex string key that is exactly 64 characters long, the third line is a hex string\n");
  fprintf(stderr, "nonce that is exactly 24 characters long, the fourth line is the decimal initial block counter\n");
  fprintf(stderr, "and the fifth line is a hex string equal to the length of the first line's characters in quotes multiplied by two.\n");
}

// Check if a ASCII string is all hex characters
int CheckHexString(unsigned char *input) {
  int len = strlen((const char *)input);
  int ind;

  for (ind = 0; ind < len; ind++) {
    if (!isxdigit(input[ind])) {
      return 1;
    }
  }
  return 0;
}

// Function that prints a result for a given regression test
int PrintRegressResultSha256(unsigned char *input, unsigned char *output, unsigned char *expected) {
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
      totalFailures += PrintRegressResultSha256(input, output, targetOutput);
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

void ChaCha20Test(void) {
  uint32_t state[16] = {0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
                        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
                        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
                        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320};
  PrintChaCha20State(state);
  ChaChaQuartRound(&state[2], &state[7], &state[8], &state[13]);
  PrintChaCha20State(state);
}

// Regression test top level function for ChaCha20
void RegressionChaCha20(FILE *testVecFile) {
  unsigned char line[(MAX_VECTOR_BYTE_LEN+1)], *input, *output, *targetOutput, *key, *nonce, *expectedOutput;
  unsigned char hexByte[3] = {0};
  unsigned int dataRead = 0, blockCounter = 1;
  unsigned long inLenBits, outLenBytes;
  int totalFailures = 0, totalTests = 0, ind;
  
  fprintf(stderr, "--- ChaCha20 Regression Test ---\n");
  while (fgets((char *)line, MAX_VECTOR_BYTE_LEN, testVecFile) != NULL) {
    dataRead = strlen((const char *)line);
    if (dataRead == 1) {
      continue;
    } else if (line[dataRead-1] != '\n') {
      PrintRegressErrorChaCha20();
      break;
    }
    // Get rid of newline on input line when copying
    line[dataRead-1] = 0x0;
    dataRead--;

    // Input line processing
    // Make sure input line is ascii within double quotes or an even sized hex string
    if ((line[0] == '"') || (line[dataRead-1] == '"')) {
      // Adjust length to ignore quotes
      dataRead -= 2;
      inLenBits = dataRead * 8;
      if (!(input = calloc(dataRead + 1, sizeof(unsigned char)))) {
        fprintf(stderr, "ERROR - ChaCha20 Regression: failed to allocate memory for input buffer. Regression will not run.\n");
        return;
      }
      if (!(output = calloc(dataRead+1, sizeof(unsigned char)))) {
        free(input);
        fprintf(stderr, "ERROR - ChaCha2 Regression: failed to allocate memory for output buffer. Regression will not run.\n");
        return;
      }
      memcpy(input, line+1, dataRead);
    } else if (!(dataRead % 2) && !CheckHexString(line)) {
      inLenBits = dataRead * 4;
      if (!(input = calloc((dataRead/2) + 1, sizeof(unsigned char)))) {
        fprintf(stderr, "ERROR - ChaCha20 Regression: failed to allocate memory for input buffer. Regression will not run.\n");
        return;
      }
      if (!(output = calloc((dataRead/2)+1, sizeof(unsigned char)))) {
        free(input);
        fprintf(stderr, "ERROR - ChaCha2 Regression: failed to allocate memory for output buffer. Regression will not run.\n");
        return;
      }
      for (ind = 0; ind < dataRead/2; ind++) {
        memcpy(hexByte, line+(2*ind), sizeof(unsigned char)*2);
        input[ind] = strtoul((const char *)hexByte, NULL, 16);
      } 
    } else {
      PrintRegressErrorChaCha20();
      break;
    }

    // Key line processing
    if(!fgets((char *)line, MAX_VECTOR_BYTE_LEN, testVecFile)) {
      PrintRegressErrorChaCha20();
      free(input); input = NULL;
      free(output); output = NULL;
      break;
    }
    dataRead = strlen((const char *)line);
    if (line[dataRead-1] == '\n') {
      line[dataRead-1] = 0x0;
      dataRead--;
    }
    if ((dataRead != (CHACHA_KEY_SIZE_BYTES * 2)) || CheckHexString(line)) {
      PrintRegressErrorChaCha20();
      free(input); input = NULL;
      free(output); output = NULL;
      break;
    }
    if (!(key = calloc(CHACHA_KEY_SIZE_BYTES + 1, sizeof(unsigned char)))) {
      fprintf(stderr, "ERROR - ChaCha20 Regression: failed to allocate memory for key buffer. Regression will not run.\n");
      free(input); input = NULL;
      free(output); output = NULL;
      break;
    }
    for (ind = 0; ind < CHACHA_KEY_SIZE_BYTES; ind++) {
      memcpy(hexByte, line+(2*ind), sizeof(unsigned char)*2);
      key[ind] = strtoul((const char *)hexByte, NULL, 16);
    }
    
    // Nonce line processing
    if(!fgets((char *)line, MAX_VECTOR_BYTE_LEN, testVecFile)) {
      PrintRegressErrorChaCha20();
      free(input); input = NULL;
      free(key); key = NULL;
      free(output); output = NULL;
      break;
    }
    dataRead = strlen((const char *)line);
    if (line[dataRead-1] == '\n') {
      line[dataRead-1] = 0x0;
      dataRead--;
    }
    if ((dataRead != (CHACHA_NONCE_SIZE_BYTES * 2)) || CheckHexString(line)) {
      PrintRegressErrorChaCha20();
      free(input); input = NULL;
      free(key); key = NULL;
      free(output); output = NULL;
      break;
    }
    if (!(nonce = calloc(dataRead + 1, sizeof(unsigned char)))) {
      fprintf(stderr, "ERROR - ChaCha20 Regression: failed to allocate memory for nonce buffer. Regression will not run.\n");
      free(input); input = NULL;
      free(key); key = NULL;
      free(output); output = NULL;
      break;
    }
    for (ind = 0; ind < CHACHA_NONCE_SIZE_BYTES; ind++) {
      memcpy(hexByte, line+(2*ind), sizeof(unsigned char)*2);
      nonce[ind] = strtoul((const char *)hexByte, NULL, 16);
    }

    // Initial Block Counter line processing
    if(!fgets((char *)line, MAX_VECTOR_BYTE_LEN, testVecFile)) {
      PrintRegressErrorChaCha20();
      free(input); input = NULL;
      free(key); key = NULL;
      free(output); output = NULL;
      break;
    }
    dataRead = strlen((const char *)line);
    if (line[dataRead-1] == '\n') {
      line[dataRead-1] = 0x0;
      dataRead--;
    }
    blockCounter = strtoul((const char *)line, NULL, 10);

    // Expected output line processing
    if(!fgets((char *)line, MAX_VECTOR_BYTE_LEN, testVecFile)) {
      PrintRegressErrorChaCha20();
      free(input); input = NULL;
      free(key); key = NULL;
      free(nonce); nonce = NULL;
      free(output); output = NULL;
      break;
    }
    dataRead = strlen((const char *)line);
    if (line[dataRead-1] == '\n') {
      line[dataRead-1] = 0x0;
      dataRead--;
    }
    outLenBytes = dataRead / 2;
    if (CheckHexString(line) || (dataRead % 2) || ((inLenBits/8) != outLenBytes)) {
      fprintf(stderr, "ERROR - invalid expected output line of text vector %d. Must be a even numbered string of hex characters double the length of the input ascii string.\n", totalTests);
      free(input); input = NULL;
      free(key); key = NULL;
      free(nonce); nonce = NULL;
      free(output); output = NULL;
      break;
    }

    if (!(expectedOutput = calloc(dataRead + 1, sizeof(unsigned char)))) {
      fprintf(stderr, "ERROR - ChaCha20 Regression: failed to allocate memory for expected output buffer. Regression will not run.\n");
      free(input); input = NULL;
      free(key); key = NULL;
      free(nonce); nonce = NULL;
      free(output); output = NULL;
      break;
    }
    for (ind = 0; ind < outLenBytes; ind++) {
      memcpy(hexByte, line+(2*ind), sizeof(unsigned char)*2);
      expectedOutput[ind] = strtoul((const char *)hexByte, NULL, 16);
    }

    // Perform Encryption
    ErikChaCha20Encrypt(input, key, nonce, blockCounter, output);
    
    /* Compared the output to expected output for result and report failures.*/
    if (memcmp(output, expectedOutput, outLenBytes)) {
      fprintf(stderr, "- TEST %d FAILED\n", totalTests);
      fprintf(stderr, "   - Differences:\n");
      for (ind=0; ind < outLenBytes; ind++) {
        if (expectedOutput[ind] != output[ind]) {
          fprintf(stderr, "       - index %d, expected 0x%02x, received 0x%02x, delta 0x%02x\n", 
                      ind, expectedOutput[ind], output[ind], expectedOutput[ind]^output[ind]);
        }
      }
      totalFailures++;
    }

    totalTests++;
    free(input); input = NULL;
    free(key); key = NULL;
    free(nonce); nonce = NULL;
    free(nonce); nonce = NULL;
    free(output); output = NULL;
    free(expectedOutput); expectedOutput = NULL;
  }
  fprintf(stderr, "--- Total Tests: %d ---\n", totalTests);
  fprintf(stderr, "--- Total Successes: %d ---\n", totalTests - totalFailures);
  fprintf(stderr, "--- Total Failures: %d ---\n", totalFailures);
}

// Simple help menu for a user
void PrintHelp(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, " -c <filename>: run ChaCha20 regression>\n");
  fprintf(stderr, " -g <string>: generate sha256 hash of <string>\n");
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
  unsigned int chacha20RegressFlag = 0;
  unsigned char *sha256File;
  unsigned char *chacha20File;
  unsigned char *inputStr;
  unsigned char outputsha256[SHA256_OUTPUT_BYTES+1] = {0};

  if (sizeof(unsigned long) != 8) {
    fprintf(stderr, "WARNING - SHA256: unsigned long is %lu bytes instead of expected 8. The max input length is affected.\n", sizeof(unsigned long));
  }

  if (argc == 1) {
      PrintHelp();
      return 0;
  }

  while ((c = getopt (argc, argv, "s:g:c:h")) != -1) {
    switch (c)
      {
      case 'c':
        //ChaCha20Test();
        chacha20RegressFlag = 1;
        chacha20File = (unsigned char *)optarg;
        break;
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

  if (chacha20RegressFlag) {
    if (!(testFile = fopen((const char *)chacha20File, "r"))) {
      fprintf(stderr, "ERROR - ChaCha20: Unable to open provided test vector file %s.\n", sha256File);
      return 1;
    }
    RegressionChaCha20(testFile);
    fclose(testFile);
  }
  if (sha256GenFlag) {
    inLenBits = strlen((const char *)inputStr) * 8;
    ErikSha256(inputStr, inLenBits, outputsha256);
    DumpHexString((unsigned char *)outputsha256, SHA256_OUTPUT_BITS);
    free(inputStr);
  }

  return 0;
}