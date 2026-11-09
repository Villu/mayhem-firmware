// Host stand-in: only the LoRa messages, copied field for field from firmware/common/message.hpp.
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
class Message {
   public:
    enum class ID : uint16_t { LoRaConfigure = 116, LoRaPacket = 117, LoRaRxStatus = 118, AudioBeep = 200, TXProgress = 201 };
    constexpr Message(ID id) : id{id} {}
    const ID id;
};
#include "message_lora.inc"
