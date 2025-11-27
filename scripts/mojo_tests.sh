#!/bin/bash
set -e

# Get test directory from first argument
if [ -z "$1" ]; then
    echo "Error: Test directory not provided"
    echo "Usage: $0 <test_directory>"
    exit 1
fi
test_dir="$1"

any_failed=false
echo "### ------------------------------------------------------------- ###"
while IFS= read -r test_file; do
    if ! magic run mojo run -I . "$test_file"; then
        any_failed=true
    fi
    echo "### ------------------------------------------------------------- ###"
done < <(find "$test_dir" -name "test_*.mojo" -type f | sort)

if [ "$any_failed" = true ]; then
    exit 1
fi