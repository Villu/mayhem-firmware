#pragma once
#include "dsp_types.hpp"
#include "message.hpp"
class BasebandProcessor {
   public:
    virtual ~BasebandProcessor() = default;
    virtual void execute(const buffer_c8_t& buffer) = 0;
    virtual void on_message(const Message* const) {}
};
