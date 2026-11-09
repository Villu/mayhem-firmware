#pragma once
#include <cstdint>
#include <cstddef>
namespace baseband { enum class Direction { Receive, Transmit }; }
class BasebandProcessor;
struct BasebandThread { BasebandThread(uint32_t, BasebandProcessor*, baseband::Direction) {} };
