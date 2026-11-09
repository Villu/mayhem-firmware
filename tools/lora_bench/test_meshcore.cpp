// Host test for the MeshCore group-chat wire format (firmware/application/apps/mesh/meshcore.cpp).
// Real packets captured off the air by others (michaelhart/meshcore-decoder test suite), so
// the code is held to what MeshCore nodes actually send, not to a round trip with itself.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "../../firmware/application/apps/mesh/meshcore.hpp"

using namespace meshcore;

static std::vector<uint8_t> unhex(const char* s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; s[i] && s[i + 1]; i += 2) {
        unsigned b;
        sscanf(s + i, "%2x", &b);
        v.push_back(static_cast<uint8_t>(b));
    }
    return v;
}

static bool check(bool ok, const char* what) {
    printf("%-58s %s\n", what, ok ? "PASS" : "FAIL");
    return ok;
}

int main() {
    bool ok = true;

    {  // FIPS-197 appendix C.1
        const auto key = unhex("000102030405060708090a0b0c0d0e0f");
        const auto pt = unhex("00112233445566778899aabbccddeeff");
        const auto want = unhex("69c4e0d86a7b0430d8cdb78070b4c55a");
        uint8_t ct[16], back[16];
        aes128_encrypt_block(key.data(), pt.data(), ct);
        aes128_decrypt_block(key.data(), ct, back);
        ok &= check(!memcmp(ct, want.data(), 16), "AES-128 encrypt, FIPS-197 C.1");
        ok &= check(!memcmp(back, pt.data(), 16), "AES-128 decrypt, FIPS-197 C.1");
    }
    {  // RFC 4231 test case 2 (a 4-byte key, zero padded like MeshCore's 16-byte keys)
        uint8_t key[32] = {'J', 'e', 'f', 'e'};
        const char* msg = "what do ya want for nothing?";
        uint8_t mac[32];
        hmac_sha256(key, reinterpret_cast<const uint8_t*>(msg), strlen(msg), mac);
        const auto want = unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        ok &= check(!memcmp(mac, want.data(), 32), "HMAC-SHA256, RFC 4231 case 2");
    }

    Channel pub, bot;
    make_channel(PUBLIC_KEY, 16, pub);
    hashtag_channel("#bot", bot);
    ok &= check(pub.hash == 0x11, "Public channel hash 0x11");
    ok &= check(!memcmp(bot.secret, unhex("eb50a1bcb3e4e5d7bf69a57c9dada211").data(), 16), "#bot key = SHA256(\"#bot\")[:16]");

    {  // public channel message from "🌲 Tree", then rebuilt byte for byte
        const auto pkt = unhex("150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D");
        Header h;
        GroupText g;
        const bool parsed = parse(pkt.data(), pkt.size(), h);
        const bool opened = parsed && open_group_text(pub, h, g);
        ok &= check(opened && h.route == ROUTE_FLOOD && h.type == TYPE_GRP_TXT && h.hops == 0, "real public packet parses and opens");
        const std::string sender(g.body, g.sender_len);
        ok &= check(sender == "\xF0\x9F\x8C\xB2 Tree" && std::string(g.text()) == "\xE2\x98\x81\xEF\xB8\x8F" && g.timestamp == 1758484279u,
                    "  sender, text and timestamp");
        uint8_t out[MAX_PACKET];
        const size_t n = build_group_text(pub, g.timestamp, sender.c_str(), g.text(), strlen(g.text()), out, sizeof(out));
        ok &= check(n == pkt.size() && !memcmp(out, pkt.data(), n), "  rebuilt byte-identical by build_group_text");
        Channel wrong;
        hashtag_channel("#test", wrong);
        ok &= check(!open_group_text(wrong, h, g), "  another channel does not open it");
        auto bad = pkt;
        bad.back() ^= 1;
        Header hb;
        parse(bad.data(), bad.size(), hb);
        ok &= check(!open_group_text(pub, hb, g), "  one flipped bit fails the MAC");
    }
    {  // #bot, two different senders, with 1- and 3-byte path hashes
        const auto p1 = unhex("1540cab3b15626481a5ba64247ab25766e410b026e0678a32da9f0c3946fae5b714cab170f");
        Header h;
        GroupText g;
        const bool o1 = parse(p1.data(), p1.size(), h) && open_group_text(bot, h, g);
        ok &= check(o1 && std::string(g.body, g.sender_len) == "Howl \xF0\x9F\x91\xBE" && std::string(g.text()) == "prefix 0101",
                    "#bot message from 'Howl'");
        const auto p2 = unhex("15833fa002860ccae0eed9ca78b9ab0775d477c1f6490a398bf4edc75240");
        const bool o2 = parse(p2.data(), p2.size(), h) && open_group_text(bot, h, g);
        ok &= check(o2 && h.hops == 3 && h.hash_size == 3 && h.path[0] == 0x3f && h.path[8] == 0xd9 &&
                        std::string(g.body, g.sender_len) == "Roy B V4" && std::string(g.text()) == "P",
                    "#bot message, 3 hops with 3-byte hashes");
        // A repeater adds itself to the path; the signature must not change.
        Header h0;
        parse(p1.data(), p1.size(), h0);
        std::vector<uint8_t> relayed = {p1[0], 0x01, 0xAB};
        relayed.insert(relayed.end(), p1.begin() + 2, p1.end());
        Header h1;
        parse(relayed.data(), relayed.size(), h1);
        ok &= check(payload_signature(h0) == payload_signature(h1), "signature is the same for a relayed copy");
    }
    {  // signed repeater advert
        const auto pkt = unhex(
            "11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A0"
            "37886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076"
            "D50238C5B8F85757375354522F50756765744D65736820436F75676172");
        Header h;
        AdvertInfo a;
        const bool r = parse(pkt.data(), pkt.size(), h) && read_advert(h, a);
        ok &= check(r && a.node_type == 2 && !strcmp(a.name, "WW7STR/PugetMesh Cougar") && a.has_location &&
                        a.lat_e6 == 47543968 && a.lon_e6 == -122108616 && a.key_prefix == 0x7E,
                    "repeater advert: type, name, location");
        static const uint8_t id[6] = {0x7E, 0x76, 0x62, 0x67, 0x6F, 0x7F};
        ok &= check(r && !memcmp(a.id, id, 6) && !strcmp(node_type_name(a.node_type), "repeater"),
                    "advert id = first 6 key bytes");

        NodeList list;
        const bool first = list.update(a, -90, 55, 0, 100);
        const bool again = list.update(a, -80, 60, 2, 200);
        AdvertInfo nameless = a;
        nameless.name[0] = 0;
        nameless.has_location = false;
        list.update(nameless, -70, 70, 1, 300);
        const auto& e = list.at(0);
        ok &= check(first && !again && list.count() == 1 && e.last_seen == 300 && e.rssi == -70 && e.hops == 1 &&
                        !strcmp(e.name, "WW7STR/PugetMesh Cougar") && e.has_location && e.lat_e6 == 47543968,
                    "node list: repeats update, a nameless advert keeps name and place");
        for (uint8_t i = 1; i <= NodeList::MAX; i++) {  // fill up, then one more
            AdvertInfo o = a;
            o.id[5] = i;
            o.name[0] = static_cast<char>('a' + i);
            o.name[1] = 0;
            list.update(o, -100, 0, 0, 1000 + i);
        }
        bool evicted_oldest = list.count() == NodeList::MAX;
        for (size_t i = 0; i < list.count(); i++)
            if (!memcmp(list.at(i).id, id, 6)) evicted_oldest = false;  // the first one, heard at 300
        ok &= check(evicted_oldest, "node list: full, the longest-silent node gives way");
        NodeList cut;
        AdvertInfo u = a;
        strcpy(u.name, "abcdefghijklmnopqrstuv\xF0\x9F\x8C\xB2x");  // 22 letters, a 4-byte emoji across byte 24
        cut.update(u, 0, 0, 0, 1);
        ok &= check(!strcmp(cut.at(0).name, "abcdefghijklmnopqrstuv"), "node list: a long name is cut between characters");
    }
    {  // too long to send
        uint8_t out[MAX_PACKET];
        std::string t(170, 'x');
        ok &= check(build_group_text(pub, 1, "me", t.c_str(), t.size(), out, sizeof(out)) == 0, "over-long text is refused");
        t.assign(MAX_GROUP_TEXT, 'x');
        const size_t n = build_group_text(pub, 1, "", t.c_str(), t.size(), out, sizeof(out));
        Header h;
        GroupText g;
        ok &= check(n && parse(out, n, h) && open_group_text(pub, h, g) && strlen(g.text()) == MAX_GROUP_TEXT,
                    "a 160-character text fits and round-trips");
    }

    {  // channel keys as typed in: the docs' hashtag example, hex and base64 forms
        Channel t;
        hashtag_channel("#test", t);
        ok &= check(!memcmp(t.secret, unhex("9cd8fcf22a47333b591d96a2b848b73f").data(), 16),
                    "#test key = docs/companion_protocol.md example");
        uint8_t k[32];
        ok &= check(parse_key("8b3387e9c5cdea6ac9e5edbaa115cd72", k) == 16 && !memcmp(k, PUBLIC_KEY, 16),
                    "parse_key: 32 hex digits");
        ok &= check(parse_key("8B3387E9C5CDEA6AC9E5EDBAA115CD72", k) == 16 && !memcmp(k, PUBLIC_KEY, 16),
                    "parse_key: upper-case hex");
        ok &= check(parse_key("izOH6cXN6mrJ5e26oRXNcg==", k) == 16 && !memcmp(k, PUBLIC_KEY, 16),
                    "parse_key: base64, 16 bytes");
        const auto k32 = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        ok &= check(parse_key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", k) == 32 &&
                        !memcmp(k, k32.data(), 32),
                    "parse_key: 64 hex digits");
        ok &= check(parse_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", k) == 32 && !memcmp(k, k32.data(), 32),
                    "parse_key: base64, 32 bytes");
        ok &= check(parse_key("", k) == 0 && parse_key("hello", k) == 0 &&
                        parse_key("8b3387e9c5cdea6ac9e5edbaa115cd7", k) == 0 &&
                        parse_key("izOH6cXN6mrJ5e26oRXN", k) == 0 && parse_key("izOH=cXN6mrJ5e26oRXNcg==", k) == 0,
                    "parse_key: refuses short, odd and malformed text");
    }

    printf("\n%s\n", ok ? "ALL PASS" : "SOME FAILED");
    return ok ? 0 : 1;
}
