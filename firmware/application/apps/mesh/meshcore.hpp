/*
 * This file is part of PortaPack.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * MeshCore wire format, the part a group chat needs: packet header and path, group
 * channels (key -> hash), and GRP_TXT build / open (AES-128-ECB + 2-byte HMAC-SHA256,
 * "encrypt then MAC"). Written from MeshCore's own sources and docs (src/Packet.h,
 * src/Mesh.cpp, src/Utils.cpp, src/helpers/BaseChatMesh.cpp, docs/packet_format.md,
 * docs/payloads.md) and held to real captured packets in tools/lora_bench/test_meshcore.cpp.
 *
 * MeshCore is a separate network from Meshtastic: other frequency, other sync word,
 * other packet format, other keys. Nothing in here touches the Meshtastic code, and
 * the app keeps its settings apart (MeshSettings::mc). Not affiliated with MeshCore.
 */

#ifndef __MESHCORE_HPP__
#define __MESHCORE_HPP__

#include <cstdint>
#include <cstddef>

namespace meshcore {

// LoRa sync word every MeshCore radio uses (RADIOLIB_SX126X_SYNC_WORD_PRIVATE), and the
// preamble length it sends (RadioLibWrapper::preambleLengthForSF).
constexpr uint8_t SYNC_WORD = 0x12;
constexpr uint8_t preamble_len(uint8_t sf) { return sf <= 8 ? 32 : 16; }

constexpr size_t MAX_PACKET = 255;        // MAX_TRANS_UNIT
constexpr size_t MAX_PAYLOAD = 184;       // MAX_PACKET_PAYLOAD
constexpr size_t MAX_GROUP_TEXT = 160;    // MAX_TEXT_LEN: what the apps allow per message
constexpr size_t MAX_SENDER_NAME = 31;    // a node name in an advert

enum Route : uint8_t { ROUTE_TRANSPORT_FLOOD = 0,
                       ROUTE_FLOOD = 1,
                       ROUTE_DIRECT = 2,
                       ROUTE_TRANSPORT_DIRECT = 3 };

enum Type : uint8_t { TYPE_REQ = 0,
                      TYPE_RESPONSE = 1,
                      TYPE_TXT_MSG = 2,
                      TYPE_ACK = 3,
                      TYPE_ADVERT = 4,
                      TYPE_GRP_TXT = 5,
                      TYPE_GRP_DATA = 6,
                      TYPE_ANON_REQ = 7,
                      TYPE_PATH = 8,
                      TYPE_TRACE = 9,
                      TYPE_MULTIPART = 10,
                      TYPE_CONTROL = 11,
                      TYPE_RAW_CUSTOM = 15 };

const char* type_name(uint8_t type);

// Radio settings the MeshCore apps offer. Index 0 is the European default, which is
// also what the firmware is built with (LORA_FREQ 869.618, BW 62.5, SF 8; CR 4/8 in
// every current app table).
struct Preset {
    const char* name;
    uint32_t freq_hz;
    uint32_t bw_hz;
    uint8_t sf;
    uint8_t cr;  // 5..8 = 4/5..4/8
};
extern const Preset PRESETS[];
extern const size_t NUM_PRESETS;

// The "Public" channel every MeshCore companion starts with (docs/faq.md).
extern const uint8_t PUBLIC_KEY[16];

// A group channel. The firmware keeps a 32-byte secret: a 16-byte key is zero padded,
// AES-128 takes the first 16 bytes, the HMAC takes all 32, and the one-byte channel
// hash is the first byte of SHA-256 over the key exactly as given (16 or 32 bytes).
struct Channel {
    uint8_t secret[32]{};
    uint8_t hash{0};
};
bool make_channel(const uint8_t* key, size_t key_len, Channel& out);
// "#name" channels: the key is the first 16 bytes of SHA-256 of the name, '#' included.
bool hashtag_channel(const char* name, Channel& out);
// A channel secret as people pass it around: 32 or 64 hex digits (what the apps show),
// or base64 (what the firmware's addChannel takes). Returns the key length, 16 or 32,
// or 0 when the text is neither.
size_t parse_key(const char* text, uint8_t out[32]);

// The fixed part of every packet: header byte, optional transport codes, path.
struct Header {
    uint8_t route{0};
    uint8_t type{0};
    uint8_t version{0};
    bool has_transport{false};
    uint16_t transport[2]{};
    uint8_t hash_size{1};  // bytes per path entry
    uint8_t hops{0};
    const uint8_t* path{nullptr};
    const uint8_t* payload{nullptr};
    size_t payload_len{0};
};
bool parse(const uint8_t* pkt, size_t len, Header& out);

// A short fingerprint of what a packet carries, the same for every copy a repeater
// floods (the path grows, the payload does not). For dropping repeats and for knowing
// our own message when a repeater sends it back.
uint32_t payload_signature(const Header& h);

// Group text, as BaseChatMesh::sendGroupMessage builds it: plaintext = timestamp (4, LE)
// + flags (0 = plain text) + "sender: text", then encrypt-then-MAC, behind the channel
// hash. Flood route, no path. Returns the packet length, or 0 when it does not fit.
size_t build_group_text(const Channel& ch,
                        uint32_t timestamp,
                        const char* sender,
                        const char* text,
                        size_t text_len,
                        uint8_t* out,
                        size_t cap);

struct GroupText {
    uint32_t timestamp{0};
    uint8_t txt_type{0};  // 0 = plain text
    uint8_t attempt{0};
    // "sender: text" split at the first ": ", as the apps do.
    char body[MAX_PAYLOAD + 1]{};
    size_t body_len{0};
    bool has_sender{false};
    size_t sender_len{0};
    const char* text() const { return body + (has_sender ? sender_len + 2 : 0); }
};
// Checks the channel hash and the MAC, then decrypts. false = not this channel, or damaged.
bool open_group_text(const Channel& ch, const Header& h, GroupText& out);

// Node name and flags from an advert's app data (signature NOT checked: Ed25519 is
// more code than a name is worth here).
struct AdvertInfo {
    uint8_t node_type{0};  // 1 chat, 2 repeater, 3 room, 4 sensor
    bool has_location{false};
    int32_t lat_e6{0}, lon_e6{0};
    char name[MAX_SENDER_NAME + 1]{};
    uint8_t key_prefix{0};  // first byte of the public key = its hash in paths
    uint8_t id[6]{};        // first six bytes of the public key: how the apps tell nodes apart
};
bool read_advert(const Header& h, AdvertInfo& out);
const char* node_type_name(uint8_t node_type);  // "companion", "repeater", ...

// The MeshCore nodes heard, from their adverts: a few, kept apart from Meshtastic's node
// table (other identities, no routing role). Full: the one heard longest ago gives way.
class NodeList {
   public:
    static constexpr size_t MAX = 8;
    static constexpr size_t NAME_LEN = 24;  // a MeshCore name is up to 31; the list shows 14
    struct Entry {
        uint8_t id[6];
        char name[NAME_LEN + 1];
        uint8_t type;
        uint8_t hops;
        bool has_location;
        int8_t rssi;
        int16_t snr_tenths;
        int32_t lat_e6, lon_e6;
        uint32_t last_seen;  // caller's clock (app ticks); 0 = unused slot
    };
    // Record an advert. Returns true when the node is new to the list.
    bool update(const AdvertInfo& a, int8_t rssi, int16_t snr_tenths, uint8_t hops, uint32_t now);
    size_t count() const { return count_; }
    const Entry& at(size_t i) const { return e_[i]; }

   private:
    Entry e_[MAX]{};
    size_t count_{0};
};

// Building blocks, public so the host test can reach them.
void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void aes128_decrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void hmac_sha256(const uint8_t key[32], const uint8_t* msg, size_t len, uint8_t out[32]);

}  // namespace meshcore

#endif /* __MESHCORE_HPP__ */
