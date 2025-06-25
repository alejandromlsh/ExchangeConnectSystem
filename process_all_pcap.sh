#!/bin/bash

# Simple PCAP Parser Test Script
# Runs the current pcap_parser on all PCAP files for testing

# Configuration
PCAP_DIR="./pcap_files"
BUILD_DIR="./build"
PARSER_EXECUTABLE="pcap_parser"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=============================================="
echo "PCAP PARSER - SIMPLE TEST RUNNER"
echo "=============================================="
echo

# Check if parser exists
if [ ! -f "$BUILD_DIR/$PARSER_EXECUTABLE" ]; then
    echo -e "${RED}ERROR:${NC} Parser executable not found at $BUILD_DIR/$PARSER_EXECUTABLE"
    exit 1
fi

# Check if PCAP directory exists
if [ ! -d "$PCAP_DIR" ]; then
    echo -e "${RED}ERROR:${NC} PCAP directory not found: $PCAP_DIR"
    exit 1
fi

# Get list of PCAP files
PCAP_FILES=$(find "$PCAP_DIR" -name "*.pcap" | sort)
TOTAL_FILES=$(echo "$PCAP_FILES" | wc -l)

if [ $TOTAL_FILES -eq 0 ]; then
    echo -e "${RED}ERROR:${NC} No PCAP files found in $PCAP_DIR"
    exit 1
fi

echo -e "${BLUE}Found $TOTAL_FILES PCAP files to test${NC}"
echo

# Process each file
count=0
for pcap_file in $PCAP_FILES; do
    count=$((count + 1))
    filename=$(basename "$pcap_file")
    
    echo -e "${BLUE}[$count/$TOTAL_FILES] Testing: $filename${NC}"
    
    # Run parser with ONLY the PCAP file (no second argument)
    if "$BUILD_DIR/$PARSER_EXECUTABLE" "$pcap_file" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ SUCCESS${NC}"
    else
        echo -e "${RED}✗ FAILED${NC}"
    fi
    
    echo "----------------------------------------"
done

echo
echo -e "${BLUE}Testing complete!${NC}"
