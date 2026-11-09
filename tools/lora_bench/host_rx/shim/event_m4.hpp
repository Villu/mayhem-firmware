#pragma once
#include <memory>
#include "baseband_processor.hpp"
struct EventDispatcher {
    explicit EventDispatcher(std::unique_ptr<BasebandProcessor>) {}
    void run() {}
};
