#!/bin/sh

if [ "$#" -gt 1 ]; then
    echo "Usage: $0 [BUILD_TYPE]"
    exit 1
fi

BUILD_TYPE="$1"

if [ -z "$BUILD_TYPE" ]; then
    BUILD_TYPE="Release"
fi

rm -rf build 2>/dev/null
mkdir build && cd build || exit 2
cmake .. -DCMAKE_BUILD_TYPE:STRING="$BUILD_TYPE" -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE
cmake --build . -j

