// Runs the firmware's LoRa receive baseband (firmware/baseband/proc_lora.cpp, compiled for the
// host) over a 2 MS/s int8 I/Q capture laid out the way the PortaPack's M4 sees it: the main
// channel at +500 kHz (the receiver tunes fs/4 low). Prints every frame each chain delivers.
//
//   host_rx CAPTURE.cs8 SF BW CR [AUX_SF AUX_BW AUX_CR AUX_OFFSET_HZ]
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <memory>
#include "proc_lora.hpp"
#include "portapack_shared_memory.hpp"

SharedMemory shared_memory;

int main(int argc, char** argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s CAPTURE.cs8 SF BW CR [AUX_SF AUX_BW AUX_CR AUX_OFFSET_HZ]\n", argv[0]);
        return 2;
    }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    std::vector<int8_t> raw;
    {
        int8_t tmp[65536];
        size_t n;
        while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0) raw.insert(raw.end(), tmp, tmp + n);
        fclose(f);
    }
    int frames[2] = {0, 0}, bad[2] = {0, 0}, busy_edges = 0;
    size_t buf_no = 0;
    shared_memory.application_queue.sink = [&](const Message& m) {
        if (m.id == Message::ID::LoRaPacket) {
            const auto& p = static_cast<const LoRaPacketMessage&>(m);
            const int net = p.net & 1;
            frames[net]++;
            if (p.crc_state != LoRaPacketMessage::CRC_OK) bad[net]++;
            printf("t=%7.3fs net=%d len=%3u crc=%s rssi=%d snr=%.1f  ", buf_no * 2048 / 2e6, p.net, p.length,
                   p.crc_state == 1 ? "ok " : (p.crc_state == 2 ? "BAD" : "?  "), p.rssi, p.snr_tenths / 10.0);
            for (unsigned i = 0; i < p.length && i < 24; i++) printf("%02x", p.data[i]);
            printf(p.length > 24 ? "...\n" : "\n");
        } else if (m.id == Message::ID::LoRaRxStatus) {
            busy_edges++;
        }
    };
    auto proc = std::make_unique<LoRaProcessor>();
    LoRaConfigureMessage cfg{static_cast<uint8_t>(atoi(argv[2])), static_cast<uint32_t>(atoi(argv[3])),
                             static_cast<uint8_t>(atoi(argv[4])), 0};
    if (argc >= 9) {
        cfg.aux_spreading_factor = static_cast<uint8_t>(atoi(argv[5]));
        cfg.aux_bandwidth = static_cast<uint32_t>(atoi(argv[6]));
        cfg.aux_coding_rate = static_cast<uint8_t>(atoi(argv[7]));
        cfg.aux_offset_hz = atoi(argv[8]);
    }
    proc->on_message(&cfg);
    std::vector<complex8_t> buf(2048);
    const size_t nsamp = raw.size() / 2;
    for (size_t s = 0; s + 2048 <= nsamp; s += 2048, buf_no++) {
        for (size_t i = 0; i < 2048; i++) buf[i] = complex8_t{raw[2 * (s + i)], raw[2 * (s + i) + 1]};
        const buffer_c8_t b{buf.data(), 2048, 2000000};
        proc->execute(b);
    }
    printf("main chain: %d frames (%d not CRC-ok); aux chain: %d frames (%d not CRC-ok); busy edges %d\n",
           frames[0], bad[0], frames[1], bad[1], busy_edges);
    return 0;
}
