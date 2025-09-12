#!/bin/bash


# Define the source file and the output executable name
V1_SOURCE_FILE="version1.c"
V2_SOURCE_FILE="version2.c"
V1_EXECUTABLE="ver1"
V2_EXECUTABLE="ver2"

# Check if the source file and the Makefile exists
echo "=== Checking for source file and Makefile... ==="

if [[ ! -f "$V1_SOURCE_FILE" ]]; then
    echo "Error: Source file '$V1_SOURCE_FILE' not found!"
    exit 1
fi

if [[ ! -f "$V2_SOURCE_FILE" ]]; then
    echo "Error: Source file '$V2_SOURCE_FILE' not found!"
    exit 1
fi

if [[ ! -f "Makefile" ]]; then
    echo "Error: Makefile not found!"
    exit 1
fi

# Compile the program using make
echo "=== Compiling the program using make... ==="
make clean
make

# Check if the compilation was successful
if [[ $? -ne 0 ]]; then
    echo "Error: Compilation failed!"
    exit 1
fi

if [ ! -f "$V1_EXECUTABLE" ]; then
    echo "Error: The executable '$V1_EXECUTABLE' was not created by the Makefile."
    exit 1
fi

if [ ! -f "$V2_EXECUTABLE" ]; then
    echo "Error: The executable '$V2_EXECUTABLE' was not created by the Makefile."
    exit 1
fi

# Clear previous fprint.out and write.out files
echo "=== Clearing previous fprint.out, write.out, and output files... ==="
rm -f fprint.out write.out v1_times.txt v2_times.txt

# Run version1 1000 times and record execution times
echo "=== Running the version1 1000 times... ==="
for i in {1..1000}
do
    /usr/bin/time -p -o v1_times.txt -a ./ver1 > /dev/null
done
echo "=== 1000 version1 runs are complete ==="

# Run version2 1000 times and record execution times
echo "=== Running the version2 1000 times... ==="
for i in {1..1000}
do
    /usr/bin/time -p -o v2_times.txt -a ./ver2 > /dev/null
done
echo "=== 1000 version2 runs are complete ==="