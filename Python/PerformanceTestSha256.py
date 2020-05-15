import matplotlib.pyplot as plt
import numpy as np 
import os
import random
import string
import subprocess
import sys
import time

# Hardcoding location of source code to use within this repository
SRC_CODE_DIR_PATH  = "../C/"
EXEC_NAME = "CryptoTestC"

# Function to generate a random ascii string of a given length
def GenRandString(length):
    new_str = "".join([random.choice(string.ascii_letters + string.digits) for x in range(length)])
    return new_str

# Function to calculate hamming weight of a passed in string
def GetStrHammingWeight(string):
    weight = 0
    for char in string:
        num_char = ord(char)
        while num_char != 0:
            if num_char & 1:
                weight += 1
            num_char = num_char >> 1
    return weight

# Simple function to generate a plot showing the duration
# of Sha256 runs for randomly generate ascii string inputs.
# Plot: x-axis = hamming weights, y-axis = raw time.time duration
def Sha256HammingWeightDurationTest():
    cmd = SRC_CODE_DIR_PATH + EXEC_NAME
    str_length = 10000
    num_data_points = 20000
    h_weights = []
    times = []

    if os.path.exists(cmd) == False:
        print("compiling...")
        output = subprocess.check_output(["make", "-C", SRC_CODE_DIR_PATH])

    for i in range(0, num_data_points):
        if (i % 100) == 0:
            print("Iteration %d" % (i))

        test_str = GenRandString(str_length)
        test_weight = GetStrHammingWeight(test_str)
        h_weights.append(test_weight)
        start_time = time.time()
        output = subprocess.check_output([cmd, "-g", test_str])
        end_time = time.time()
        times.append((end_time - start_time))
    
    plt.scatter(h_weights, times, color="red")
    plt.show()

# Main
if __name__ == "__main__":
    Sha256HammingWeightDurationTest()
