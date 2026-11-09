#pragma once
#include <cstdint>
#include <functional>
#include "message.hpp"
struct HostQueue {
    std::function<void(const Message&)> sink;
    template <typename T> bool push(const T& m) { if (sink) sink(m); return true; }
};
struct SharedMemory { HostQueue application_queue; uint16_t m4_buffer_missed{0}; };
extern SharedMemory shared_memory;
