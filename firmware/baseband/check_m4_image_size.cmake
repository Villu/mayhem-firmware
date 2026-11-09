# cmake -DBIN=<image.bin> -DMAX=<bytes> -P check_m4_image_size.cmake
#
# A baseband image is unpacked into portapack::memory::map::m4_code (32 KiB) with no
# bounds check, and shared_memory - the M0/M4 message queues - starts right behind it.
# The M4 linker script cannot catch an overflow on Praline, where it is given the whole
# 72 KiB bank, so a baseband that grows past the area builds cleanly and then silently
# corrupts the queues on the device. Fail the build instead.
file(SIZE "${BIN}" size)
if(size GREATER MAX)
	file(REMOVE "${BIN}")
	math(EXPR over "${size} - ${MAX}")
	message(FATAL_ERROR "${BIN}: ${size} bytes is ${over} over the ${MAX}-byte M4 code area")
endif()
