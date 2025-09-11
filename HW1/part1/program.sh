#!/bin/bash

# Define the source file and the output executable name
SOURCE_FILE="program.c"
EXECUTABLE="prog"

# Check if the source file and the Makefile exists
echo "=== Checking for source file and Makefile... ==="

if [[ ! -f "$SOURCE_FILE" ]]; then
    echo "Error: Source file '$SOURCE_FILE' not found!"
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

if [ ! -f "$EXECUTABLE" ]; then
    echo "Error: The executable '$EXECUTABLE' was not created by the Makefile."
    exit 1
fi

# Clear previous fprint.out and write.out files
echo "=== Clearing previous fprint.out and write.out files... ==="
rm -f fprint.out write.out

# Run the program 1000 times and record the patterns of interleaving of “f1” and “f2” calls
echo "=== Running the program 1000 times... ==="
for i in {1..1000}; do
    ./"$EXECUTABLE" >> run.txt
done

echo "=== 1000 runs are complete ==="

f1_before_f2=0
f2_before_f1=0

# Analyze run.txt
while read -r line1 && read -r line2
do
    if [[ "$line1" == *"f1"* && "$line2" == *"f2"* ]]; then
        ((f1_before_f2++))
    elif [[ "$line1" == *"f2"* && "$line2" == *"f1"* ]]; then
        ((f2_before_f1++))
    fi
done < run.txt

echo "f1 before f2: $f1_before_f2 times"
echo "f2 before f1: $f2_before_f1 times"