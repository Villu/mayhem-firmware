// Host test for the MeshCore wire format (firmware/application/apps/mesh/meshcore.cpp) and the
// Ed25519 it needs (mesh_pki.cpp). Group texts and adverts are real packets captured off the
// air by others (michaelhart/meshcore-decoder test suite), and the signing and direct-message
// vectors come from independent implementations, so the code is held to what MeshCore nodes
// send and not to a round trip with itself.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "../../firmware/application/apps/mesh/meshcore.hpp"
#include "../../firmware/application/apps/mesh/mesh_pki.hpp"

using namespace meshcore;

// Vectors for the MeshCore direct-message tests, made by independent Python references:
// pycryptodome Ed25519 (RFC 8032), a pure-Python X25519 over the Edwards->Montgomery map, and
// pycryptodome AES/HMAC for the packets.
// prv64, pub, msg, sig  (pycryptodome Ed25519)
static const char* const ED_VEC[][4] = {
    {"ae07d5b3fca5b9a80719cf4364790be45193f3bb10b42e2996337f9f0f55c0e499bf23ae8f7af9a93cb7aef7c3245a9d495c39d70f62707af5a6c654ee6cb7c8", "2fa3c670e1fb2f12fb6b3c04a3014dc627f9fb9ec099840cbe13a878ff73e1dd", "", "00d9286174bad530a4b92f85f0a6d010e2ab4fafe25be6f4d18b4e80f5594e44a8151e3fb610e32dd41b8c7fb20c1398f4285abf957bd51f654a90bd117a4203"},
    {"c71fec4cb829425eeac19e36f42336b821581dea964d9dbf241f03f8413842bf333defdf6b85cf7646d30aa0ce8f17fa3c84b05e2d8a173c46b8000125e984fb", "8fd73e9631a5a47e4533a6cf3ccd708255d1c80e20ead0e41dd3bb5ca7d9fd1a", "a0aeb3fee9232f8af2211f9ee491c5b10becb5563bfc1e6f93427ecbc8fe2955e5cd8e46dc8ed4b7c2764d2a5a4d767706f85d8690024ad6bda3401be9c8cbccc935f6cd1f61226ae15338ae1a34004d33ba0d246ac04c81b1baf23e3bf9eef5f79f2b4934af87f5520b69b94b0d982e85bb55b672a872637acd7466fcb60e0e", "8587a75908ec7d84ba418a809116516f03ff17b45c293b147b1b68307a7ea9c7e75ef5c32cf425a827c84d01627a9a62728d26367309544b4afcf835907e210a"}};
// shared secret (pure-Python X25519 of the Montgomery-mapped key), both sides agree
struct KeVec {
    int a, b;
    const char* shared;
};
static const KeVec KE_VEC[] = {{0, 1, "99a65215c44d9cb80f55d639501dc5fc5f27438c03e81dbb6bb27da12da5f857"}};
static const char* const DM_PRV_A = "672fc227c7fd83f9d88ddfa001ca4c5e0fd5eaa56eef4b930a658c404265d50c844a261f234a15f27114b357ae07686b213492df779d02b8dabd664a42bffc27";
static const char* const DM_PRV_B = "69ac6c88592bd03142545c5bedea87b11fa186d1c30fbc23c3235c5d025bfe820bc8358f24d641b0db5777ab7c18ee7c54c1b3a52bd502f14e89e2ee1ed19285";
static const char* const DM_ADVERT_A = "11001feb11c08abbe9c2ca45eb912cf6607327e033c3e2d9da42637912f61112b304a0d21969422cd4fbd87c11275bbb73ac75fab69f6f170827c0895fe08b65a247191bb39a4d894737b5adff6e36975d2edcfbb94838f5b02f6804d10603c0f332cf8f4c0981506f7274615061636b";  // ts 1763300000, "PortaPack"
static const char* const DM_SECRET = "3486e1d5bedf0657bb57209cb348ea286cf1bf510341503bdf9b3cd496433857";
static const char* const DM_TEXT_AB = "0900961fed247421ab93c8be4cbd6817bc0cc4500f245d9dd89f660ef8e4881cec4bf461027aca66ddb9f565a3e5ac7fb743a9f3b14a";  // ts 1763300005, attempt 1
static const char* const DM_TEXT_AB_ACK = "ffefe682";
static const char* const DM_TEXT = "Hello from the PortaPack, a direct message";
static const char* const DM_PATH_BA = "21001f962bc827bdab8a771b2bdf1787cc36915ae22e";
static const char* const DM_ACK = "0d00ffefe682";

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
                        a.lat_e6 == 47543968 && a.lon_e6 == -122108616,
                    "repeater advert: type, name, location");
        static const uint8_t id[6] = {0x7E, 0x76, 0x62, 0x67, 0x6F, 0x7F};
        ok &= check(r && !memcmp(a.pub, id, 6) && !strcmp(node_type_name(a.node_type), "repeater"),
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
            o.pub[5] = i;
            o.name[0] = static_cast<char>('a' + i);
            o.name[1] = 0;
            list.update(o, -100, 0, 0, 1000 + i);
        }
        bool evicted_oldest = list.count() == NodeList::MAX;
        for (size_t i = 0; i < list.count(); i++)
            if (!memcmp(list.at(i).pub, id, 6)) evicted_oldest = false;  // the first one, heard at 300
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

    {  // Ed25519 and the MeshCore shared secret
        using namespace meshtastic::pki;
        Sha512 sh;
        uint8_t d[64];
        sh.init();
        sh.update(reinterpret_cast<const uint8_t*>("abc"), 3);
        sh.final(d);
        ok &= check(!memcmp(d, unhex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").data(), 64),
                    "SHA-512(\"abc\") = FIPS 180-2 example");
        const auto seed = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        uint8_t prv[64], pub[32], sig[64];
        sh.init();
        sh.update(seed.data(), 32);
        sh.final(prv);
        ed25519_public(pub, prv);
        ed25519_sign(sig, nullptr, 0, pub, prv);
        ok &= check(!memcmp(pub, unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").data(), 32) &&
                        !memcmp(sig, unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").data(), 64),
                    "Ed25519: RFC 8032 test 1 (key and signature)");
        bool all = true;
        for (auto& v : ED_VEC) {
            const auto p = unhex(v[0]), u = unhex(v[1]), m = unhex(v[2]), s = unhex(v[3]);
            uint8_t p2[32], s2[64];
            ed25519_public(p2, p.data());
            ed25519_sign(s2, m.data(), m.size(), u.data(), p.data());
            all &= !memcmp(p2, u.data(), 32) && !memcmp(s2, s.data(), 64);
        }
        ok &= check(all, "Ed25519: random keys, an empty and a long message = pycryptodome");
        all = true;
        for (auto& k : KE_VEC) {
            uint8_t s1[32], s2[32];
            all &= shared_secret(unhex(ED_VEC[k.a][0]).data(), unhex(ED_VEC[k.b][1]).data(), s1);
            all &= shared_secret(unhex(ED_VEC[k.b][0]).data(), unhex(ED_VEC[k.a][1]).data(), s2);
            all &= !memcmp(s1, unhex(k.shared).data(), 32) && !memcmp(s2, s1, 32);
        }
        ok &= check(all, "shared secret: both sides agree, = Python X25519");
    }

    {  // Direct messages
        const auto prv_a = unhex(DM_PRV_A), prv_b = unhex(DM_PRV_B);
        uint8_t pub_a[32], pub_b[32], sec_a[32], sec_b[32];
        meshtastic::pki::ed25519_public(pub_a, prv_a.data());
        meshtastic::pki::ed25519_public(pub_b, prv_b.data());
        shared_secret(prv_a.data(), pub_b, sec_a);
        shared_secret(prv_b.data(), pub_a, sec_b);
        ok &= check(!memcmp(sec_a, unhex(DM_SECRET).data(), 32) && !memcmp(sec_b, sec_a, 32), "DM: shared secret");

        uint8_t pkt[MAX_PACKET];
        size_t n = build_advert(prv_a.data(), pub_a, 1763300000, NODE_CHAT, "PortaPack", pkt, sizeof(pkt));
        const auto adv = unhex(DM_ADVERT_A);
        ok &= check(n == adv.size() && !memcmp(pkt, adv.data(), n), "advert: byte-exact with the Python reference (signed)");
        Header h;
        AdvertInfo ai;
        ok &= check(parse(pkt, n, h) && read_advert(h, ai) && !strcmp(ai.name, "PortaPack") &&
                        ai.node_type == NODE_CHAT && !memcmp(ai.pub, pub_a, 32) && ai.timestamp == 1763300000,
                    "advert: reads back (name, type, key, time)");

        uint32_t ack = 0;
        n = build_direct_text(sec_a, pub_b, pub_a, 1763300005, 1, DM_TEXT, strlen(DM_TEXT), pkt, sizeof(pkt), ack);
        const auto txt = unhex(DM_TEXT_AB);
        const auto ack_ref = unhex(DM_TEXT_AB_ACK);
        const uint32_t ack_want = ack_ref[0] | (ack_ref[1] << 8) | (ack_ref[2] << 16) | (static_cast<uint32_t>(ack_ref[3]) << 24);
        ok &= check(n == txt.size() && !memcmp(pkt, txt.data(), n) && ack == ack_want,
                    "DM text: byte-exact with the Python reference, ACK too");
        static DirectText dt;
        ok &= check(parse(pkt, n, h) && is_peer_packet(h) && h.payload[0] == pub_b[0] && h.payload[1] == pub_a[0] &&
                        open_direct_text(sec_b, pub_a, h, dt) && !strcmp(dt.text, DM_TEXT) &&
                        dt.timestamp == 1763300005 && dt.attempt == 1 && dt.txt_type == 0 && dt.ack == ack_want,
                    "DM text: the recipient opens it and computes the same ACK");
        pkt[n - 1] ^= 1;
        parse(pkt, n, h);
        ok &= check(!open_direct_text(sec_b, pub_a, h, dt), "DM text: a damaged copy is refused (MAC)");
        uint8_t other[32];
        shared_secret(unhex(ED_VEC[0][0]).data(), pub_a, other);
        pkt[n - 1] ^= 1;
        parse(pkt, n, h);
        ok &= check(!open_direct_text(other, pub_a, h, dt), "DM text: another secret does not open it");

        // The recipient answers a text that came over two repeaters with a path + ACK.
        const uint8_t came[] = {0x09, 0x02, 0x5a, 0xc3, 0x00};
        Header ci;
        parse(came, sizeof(came), ci);
        n = build_path_ack(sec_b, pub_a[0], pub_b[0], ci, ack_want, pkt, sizeof(pkt));
        const auto pth = unhex(DM_PATH_BA);
        ok &= check(n == pth.size() && !memcmp(pkt, pth.data(), n), "path + ACK: byte-exact with the Python reference");
        uint32_t got = 0;
        ok &= check(parse(pkt, n, h) && open_path_ack(sec_a, h, got) && got == ack_want, "path + ACK: the sender reads the ACK");
        n = build_ack(ack_want, pkt, sizeof(pkt));
        const auto ak = unhex(DM_ACK);
        ok &= check(n == ak.size() && !memcmp(pkt, ak.data(), n) && parse(pkt, n, h) && open_ack(h, got) &&
                        got == ack_want,
                    "plain ACK: byte-exact, and reads back");

        std::string lt(MAX_DIRECT_TEXT, 'x');
        n = build_direct_text(sec_a, pub_b, pub_a, 1, 0, lt.c_str(), lt.size(), pkt, sizeof(pkt), ack);
        ok &= check(n > 0 && n <= MAX_PACKET && n - 2 <= MAX_PAYLOAD && parse(pkt, n, h) &&
                        open_direct_text(sec_b, pub_a, h, dt) && dt.text_len == MAX_DIRECT_TEXT,
                    "DM text: 160 characters fit and come back whole");
        ok &= check(!build_direct_text(sec_a, pub_b, pub_a, 1, 0, lt.c_str(), MAX_DIRECT_TEXT + 1, pkt, sizeof(pkt), ack),
                    "DM text: 161 characters are refused");
    }

    printf("\n%s\n", ok ? "ALL PASS" : "SOME FAILED");
    return ok ? 0 : 1;
}
