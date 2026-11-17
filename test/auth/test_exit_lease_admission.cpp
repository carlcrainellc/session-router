// Unit tests for exit-side lease admission (src/auth/exit_lease_admission.hpp).
// Standalone: needs only nlohmann, libsodium and Catch2 (amalgamated).
#include "auth/exit_lease_admission.hpp"

#include <catch_amalgamated.hpp>
#include <sodium.h>

#include <cstdio>
#include <fstream>
#include <set>
#include <string>

using namespace srouter::auth;
using nlohmann::json;

namespace
{
    const std::string SELLER = "testseller100000000000000000000000000000000000000000.sesh";
    const std::string OTHER_SELLER = "testseller200000000000000000000000000000000000000000.sesh";
    const std::string STRANGER = "testclient000000000000000000000000000000000000000.sesh";
    const std::string OTHER_CLIENT = "testclient100000000000000000000000000000000000000000.sesh";
    constexpr std::int64_t NOW = 1'760'000'000;

    std::string hex(const unsigned char* p, size_t n)
    {
        static const char* d = "0123456789abcdef";
        std::string s;
        for (size_t i = 0; i < n; ++i)
        {
            s.push_back(d[p[i] >> 4]);
            s.push_back(d[p[i] & 15]);
        }
        return s;
    }

    struct Issuer
    {
        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        unsigned char sk[crypto_sign_SECRETKEYBYTES];
        Issuer() { crypto_sign_keypair(pk, sk); }
        std::string pk_hex() const { return hex(pk, sizeof pk); }

        json record(
            const std::string& seller, const std::string& client, std::int64_t exp, const std::string& tid = "t1") const
        {
            const auto m = admission_message(seller, client, exp, tid);
            unsigned char sig[crypto_sign_BYTES];
            crypto_sign_detached(sig, nullptr, reinterpret_cast<const unsigned char*>(m.data()), m.size(), sk);
            return json{
                {"kind", "exit_lease_admission"},
                {"scope", "exit_lease"},
                {"v", 2},
                {"tid", tid},
                {"lock_seller_id", seller},
                {"client_sesh", client},
                {"exp", exp},
                {"sig", hex(sig, sizeof sig)}};
        }
    };

    json store(std::initializer_list<json> recs)
    {
        json a = json::object();
        int i = 0;
        for (const auto& r : recs)
            a["tid" + std::to_string(i++)] = r;
        return json{{"admissions", a}};
    }

    std::string reason(const ExitLeaseAuthResult& r) { return r.reason; }
}  // namespace

TEST_CASE("paid stranger not on any whitelist is admitted")
{
    REQUIRE(sodium_init() >= 0);
    Issuer is;
    auto s = store({is.record(SELLER, STRANGER, NOW + 3600)}).dump();
    auto r = admission_in_text(s, is.pk_hex(), SELLER, STRANGER, NOW);
    CHECK(r.allow);
    CHECK(reason(r) == "admission");
}

TEST_CASE("unpaid client (no record) is refused")
{
    Issuer is;
    auto s = store({is.record(SELLER, OTHER_CLIENT, NOW + 3600)}).dump();
    auto r = admission_in_text(s, is.pk_hex(), SELLER, STRANGER, NOW);
    CHECK_FALSE(r.allow);
    CHECK(reason(r) == "wrong_client");
    CHECK(reason(admission_in_text(R"({"admissions":{}})", is.pk_hex(), SELLER, STRANGER, NOW)) == "no_match");
}

TEST_CASE("expired lease is refused, boundary exp == now refused")
{
    Issuer is;
    CHECK(reason(admission_in_text(store({is.record(SELLER, STRANGER, NOW - 1)}).dump(), is.pk_hex(), SELLER, STRANGER, NOW))
          == "expired");
    CHECK_FALSE(admission_in_text(store({is.record(SELLER, STRANGER, NOW)}).dump(), is.pk_hex(), SELLER, STRANGER, NOW).allow);
    CHECK(admission_in_text(store({is.record(SELLER, STRANGER, NOW + 1)}).dump(), is.pk_hex(), SELLER, STRANGER, NOW).allow);
}

TEST_CASE("lease for another seller does not open this exit")
{
    Issuer is;
    auto r = admission_in_text(store({is.record(OTHER_SELLER, STRANGER, NOW + 3600)}).dump(), is.pk_hex(), SELLER, STRANGER, NOW);
    CHECK_FALSE(r.allow);
    CHECK(reason(r) == "wrong_seller");
}

TEST_CASE("forged or tampered records are refused")
{
    Issuer is, mallory;
    // Signed by someone else's key.
    CHECK(reason(admission_in_text(store({mallory.record(SELLER, STRANGER, NOW + 3600)}).dump(), is.pk_hex(), SELLER, STRANGER, NOW))
          == "bad_sig");
    // Extended exp after signing.
    auto rec = is.record(SELLER, STRANGER, NOW + 60);
    rec["exp"] = NOW + 999999;
    CHECK(reason(admission_in_text(store({rec}).dump(), is.pk_hex(), SELLER, STRANGER, NOW)) == "bad_sig");
    // Re-targeted to a different client after signing.
    auto rec2 = is.record(SELLER, OTHER_CLIENT, NOW + 3600);
    rec2["client_sesh"] = STRANGER;
    CHECK(reason(admission_in_text(store({rec2}).dump(), is.pk_hex(), SELLER, STRANGER, NOW)) == "bad_sig");
    // Changed tid after signing.
    auto rec3 = is.record(SELLER, STRANGER, NOW + 3600, "a");
    rec3["tid"] = "b";
    CHECK(reason(admission_in_text(store({rec3}).dump(), is.pk_hex(), SELLER, STRANGER, NOW)) == "bad_sig");
    // Garbage signature.
    auto rec4 = is.record(SELLER, STRANGER, NOW + 3600);
    rec4["sig"] = "zz";
    CHECK(reason(admission_in_text(store({rec4}).dump(), is.pk_hex(), SELLER, STRANGER, NOW)) == "bad_sig");
}

TEST_CASE("unsigned v1 admission records are rejected")
{
    Issuer is;
    json v1{{"kind", "exit_lease_admission"},
            {"scope", "exit_lease"},
            {"v", 1},
            {"lock_seller_id", SELLER},
            {"client_sesh", STRANGER},
            {"exp", NOW + 3600}};
    auto r = admission_in_text(store({v1}).dump(), is.pk_hex(), SELLER, STRANGER, NOW);
    CHECK_FALSE(r.allow);
    CHECK(reason(r) == "bad_record");
}

TEST_CASE("fail closed on missing issuer, bad issuer, bad file")
{
    Issuer is;
    auto s = store({is.record(SELLER, STRANGER, NOW + 3600)}).dump();
    CHECK(reason(admission_in_text(s, "", SELLER, STRANGER, NOW)) == "no_issuer");
    CHECK(reason(admission_in_text(s, "abcd", SELLER, STRANGER, NOW)) == "bad_issuer");
    CHECK(reason(admission_in_text("{not json", is.pk_hex(), SELLER, STRANGER, NOW)) == "bad_file");
    CHECK(reason(admission_in_text(s, is.pk_hex(), "", STRANGER, NOW)) == "no_match");
    // Newline injection in a field is rejected as a bad record.
    auto rec = is.record(SELLER, STRANGER, NOW + 3600);
    rec["tid"] = "x\nexit";
    CHECK(reason(admission_in_text(store({rec}).dump(), is.pk_hex(), SELLER, STRANGER, NOW)) == "bad_record");
}

TEST_CASE("record shapes: array, present-body, mixed store")
{
    Issuer is;
    json arr = json::array({is.record(SELLER, OTHER_CLIENT, NOW + 3600), is.record(SELLER, STRANGER, NOW + 3600)});
    CHECK(admission_in_text(arr.dump(), is.pk_hex(), SELLER, STRANGER, NOW).allow);
    json body{{"body", {{"admission", is.record(SELLER, STRANGER, NOW + 3600)}}}};
    CHECK(admission_in_text(body.dump(), is.pk_hex(), SELLER, STRANGER, NOW).allow);
    // An expired record and a valid one for the same client: valid wins.
    auto s = store({is.record(SELLER, STRANGER, NOW - 10, "old"), is.record(SELLER, STRANGER, NOW + 10, "new")});
    CHECK(admission_in_text(s.dump(), is.pk_hex(), SELLER, STRANGER, NOW).allow);
}

TEST_CASE("validate ordering: open/token/whitelist first, then store file")
{
    Issuer is;
    CHECK(reason(exit_lease_auth_allows(true, false, false, "", "", SELLER, STRANGER, NOW)) == "open_none");
    CHECK(reason(exit_lease_auth_allows(false, true, false, "", "", SELLER, STRANGER, NOW)) == "static_token");
    CHECK(reason(exit_lease_auth_allows(false, false, true, "", "", SELLER, STRANGER, NOW)) == "whitelist");
    CHECK(reason(exit_lease_auth_allows(false, false, false, "", is.pk_hex(), SELLER, STRANGER, NOW)) == "no_store");

    const std::string path = "exit_lease_admission_test_store.json";
    {
        std::ofstream f{path};
        f << store({is.record(SELLER, STRANGER, NOW + 3600)}).dump();
    }
    CHECK(reason(exit_lease_auth_allows(false, false, false, path, "", SELLER, STRANGER, NOW)) == "no_issuer");
    auto r = exit_lease_auth_allows(false, false, false, path, is.pk_hex(), SELLER, STRANGER, NOW);
    CHECK(r.allow);
    CHECK(reason(r) == "admission");
    CHECK_FALSE(exit_lease_auth_allows(false, false, false, path, is.pk_hex(), SELLER, OTHER_CLIENT, NOW).allow);
    CHECK(reason(exit_lease_auth_allows(false, false, false, "/nonexistent/x.json", is.pk_hex(), SELLER, STRANGER, NOW))
          == "bad_file");
    std::remove(path.c_str());
}

TEST_CASE("admission result carries the latest valid exp (renewal)")
{
    Issuer is;
    auto s = store({is.record(SELLER, STRANGER, NOW + 60, "a"), is.record(SELLER, STRANGER, NOW + 600, "b")});
    auto r = admission_in_text(s.dump(), is.pk_hex(), SELLER, STRANGER, NOW);
    CHECK(r.allow);
    CHECK(r.exp == NOW + 600);
}

TEST_CASE("lease tracker: expired leases come due, renewal extends, sweep catches revocation")
{
    LeaseTracker<std::string> t{1000};
    t.admitted("buyer", NOW + 100);
    t.admitted("other", NOW + 10'000);

    // First call is a sweep: everything is re-checked once.
    CHECK(t.due(NOW).size() == 2);
    // Inside the sweep interval and before exp: nothing due.
    CHECK(t.due(NOW + 5).empty());
    // At exp the buyer is due even between sweeps; the long lease is not.
    auto d = t.due(NOW + 100);
    REQUIRE(d.size() == 1);
    CHECK(d[0] == "buyer");
    // Caller found a renewed record: tracker moves the clock.
    t.admitted("buyer", NOW + 500);
    CHECK(t.due(NOW + 101).empty());
    // Next sweep (interval after the last sweep at NOW) re-checks all, catching revocation.
    CHECK(t.due(NOW + 1000).size() == 2);
    t.forget("buyer");
    CHECK(t.size() == 1);
    CHECK_FALSE(t.exp_of("buyer").has_value());
}

TEST_CASE("lease expiry end to end: re-validate at exp drops the session")
{
    // Mirrors SessionEndpoint::enforce_lease_expiry with a fake session table.
    Issuer is;
    const std::string path = "exit_lease_expiry_store.json";
    {
        std::ofstream f{path};
        f << store({is.record(SELLER, STRANGER, NOW + 30)}).dump();
    }
    std::set<std::string> sessions{STRANGER};
    LeaseTracker<std::string> t{15};

    auto validate = [&](const std::string& remote, std::int64_t now) {
        auto r = exit_lease_auth_allows(false, false, false, path, is.pk_hex(), SELLER, remote, now);
        if (r.allow)
            t.admitted(remote, r.exp);
        return r;
    };
    auto enforce = [&](std::int64_t now) {
        for (const auto& k : t.due(now))
        {
            auto r = exit_lease_auth_allows(false, false, false, path, is.pk_hex(), SELLER, k, now);
            if (r.allow)
                t.admitted(k, r.exp);
            else
            {
                t.forget(k);
                sessions.erase(k);  // close_session
            }
        }
    };

    REQUIRE(validate(STRANGER, NOW).allow);
    enforce(NOW + 1);
    CHECK(sessions.count(STRANGER) == 1);
    enforce(NOW + 29);
    CHECK(sessions.count(STRANGER) == 1);
    enforce(NOW + 30);  // exp reached
    CHECK(sessions.count(STRANGER) == 0);
    CHECK(t.size() == 0);
    std::remove(path.c_str());
}

TEST_CASE("store cache reloads only when the file changes")
{
    Issuer is;
    const std::string path = "exit_lease_cache_store.json";
    auto write = [&](const json& j) {
        // Atomic rename like admission.py (new inode).
        const std::string tmp = path + ".tmp";
        {
            std::ofstream f{tmp};
            f << j.dump();
        }
        std::rename(tmp.c_str(), path.c_str());
    };
    write(store({is.record(SELLER, OTHER_CLIENT, NOW + 3600)}));
    auto& c = StoreCache::instance();
    const auto loads0 = c.loads();
    CHECK_FALSE(exit_lease_auth_allows(false, false, false, path, is.pk_hex(), SELLER, STRANGER, NOW).allow);
    CHECK_FALSE(exit_lease_auth_allows(false, false, false, path, is.pk_hex(), SELLER, STRANGER, NOW).allow);
    CHECK(c.loads() == loads0 + 1);
    write(store({is.record(SELLER, OTHER_CLIENT, NOW + 3600), is.record(SELLER, STRANGER, NOW + 3600)}));
    CHECK(exit_lease_auth_allows(false, false, false, path, is.pk_hex(), SELLER, STRANGER, NOW).allow);
    CHECK(c.loads() == loads0 + 2);
    std::remove(path.c_str());
    CHECK(reason(exit_lease_auth_allows(false, false, false, path, is.pk_hex(), SELLER, STRANGER, NOW)) == "bad_file");
}
