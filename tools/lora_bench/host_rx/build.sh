#!/bin/bash
# Build host_rx from the firmware's own receive sources (copied, not edited, so the shim
# headers in shim/ stand in for ChibiOS, the message bus and the DSP intrinsics).
set -e
cd "$(dirname "$0")"
FW=../../../firmware
mkdir -p build
cp $FW/baseband/proc_lora.cpp $FW/baseband/proc_lora.hpp build/
# On the M4 'long' is 32 bits, and the receiver's window arithmetic relies on it wrapping
# like one: (long)h0 + (int)k * (uint32_t)n is unsigned 32-bit maths cast back. Give the
# host copy the same width so it computes what the device computes.
sed -i 's/\blong\b/int32_t/g' build/proc_lora.cpp
python3 gen_messages.py $FW/common/message.hpp shim/message_lora.inc
FLAGS="-w -std=c++17 -O2 -g -DLPC43XX_M4 -Wno-psabi -Ishim -Ibuild -I$FW/baseband -I$FW/common"
g++ $FLAGS -Dmain=firmware_main -c build/proc_lora.cpp -o build/proc_lora.o
g++ $FLAGS -c $FW/baseband/dsp_decimate.cpp -o build/dsp_decimate.o
g++ $FLAGS -o host_rx host_rx.cpp build/proc_lora.o build/dsp_decimate.o
if [ "$1" = "--debug" ]; then   # SF11_DEBUG markers (0xEE/0xED/0xEA/0xE9 frames) as well
  sed 's/#define SF11_DEBUG 0/#define SF11_DEBUG 1/' build/proc_lora.cpp > build/proc_lora_dbg.cpp
  g++ $FLAGS -w -Dmain=firmware_main -c build/proc_lora_dbg.cpp -o build/proc_lora_dbg.o
  g++ $FLAGS -o host_rx_dbg host_rx.cpp build/proc_lora_dbg.o build/dsp_decimate.o
fi
echo built host_rx
