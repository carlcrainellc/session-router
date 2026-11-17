#pragma once

// Exit-side lease admission.
//
// A buyer who paid for seller S is admitted to S's exit without any
// hand-edited whitelist. The seller's own admission issuer (seller pack
// daemon, which checks payment on chain) writes signed admission records into
// a local store file. The exit admits an inbound client `remote` only when a
// record:
//
//   kind           == "exit_lease_admission"
//   scope          == "exit_lease"
//   v              == 2
//   lock_seller_id == this exit's own client .sesh   (exact string)
//   client_sesh    == remote.to_string()             (exact string)
//   exp            >  now (unix seconds)
//   sig            == hex Ed25519 detached signature by the issuer key over
//                     admission_message(lock_seller_id, client_sesh, exp, tid)
//
// Store file: env SR_EXIT_LEASE_ADMISSIONS (path). Any JSON shape; every
// object anywhere in the document is considered (admissions map keyed by tid,
// an array, or a single {"admission": {...}}).
// Issuer key: env SR_EXIT_LEASE_ISSUER_PUBKEY (64 hex chars, Ed25519 public).
//
// Fail closed: no store, unreadable/oversized/invalid JSON, no issuer key, or
// a bad issuer key admits nobody by this path. Unsigned v1 records are
// NOT accepted. Static token / whitelist / explicit open behaviour is
// unchanged and evaluated first.

#include <nlohmann/json.hpp>
#include <sodium/crypto_sign.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace srouter::auth
{
    struct ExitLeaseAuthResult
    {
        bool allow{false};
        // Stable literal: open_none, static_token, whitelist, admission, no_store,
        // no_issuer, bad_issuer, bad_file, no_match, wrong_client, wrong_seller,
        // expired, bad_record, bad_sig.
        const char* reason{"no_match"};
        // For reason == "admission": the latest exp (unix seconds) among matching valid records.
        std::int64_t exp{0};
    };

    inline constexpr std::string_view ADMISSION_DOMAIN = "srnet-exit-admission/v2";
    inline constexpr size_t ADMISSION_MAX_FILE = 4u << 20;

    /// Exact bytes the issuer signs. Newline separated; fields cannot contain '\n'
    /// (rejected on parse).
    inline std::string admission_message(
        std::string_view seller, std::string_view client, std::int64_t exp, std::string_view tid)
    {
        std::string m;
        m.reserve(ADMISSION_DOMAIN.size() + seller.size() + client.size() + tid.size() + 32);
        m.append(ADMISSION_DOMAIN).push_back('\n');
        m.append(seller).push_back('\n');
        m.append(client).push_back('\n');
        m.append(std::to_string(exp)).push_back('\n');
        m.append(tid);
        return m;
    }

    namespace detail
    {
        inline int hexval(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        }

        template <size_t N>
        std::optional<std::array<unsigned char, N>> from_hex(std::string_view h)
        {
            if (h.size() != 2 * N)
                return std::nullopt;
            std::array<unsigned char, N> out{};
            for (size_t i = 0; i < N; ++i)
            {
                const int a = hexval(h[2 * i]), b = hexval(h[2 * i + 1]);
                if (a < 0 || b < 0)
                    return std::nullopt;
                out[i] = static_cast<unsigned char>((a << 4) | b);
            }
            return out;
        }

        using PubKey = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>;

        struct Scan
        {
            bool saw_any{false}, wrong_seller{false}, wrong_client{false}, expired{false}, bad{false},
                bad_sig{false};
        };

        inline bool get_str(const nlohmann::json& o, const char* k, std::string& out)
        {
            auto it = o.find(k);
            if (it == o.end() || !it->is_string())
                return false;
            out = it->get<std::string>();
            return out.find('\n') == std::string::npos;
        }

        inline bool check_record(
            const nlohmann::json& o,
            const PubKey& issuer,
            std::string_view this_seller,
            std::string_view remote,
            std::int64_t now,
            Scan& sc,
            std::int64_t& exp_out)
        {
            std::string kind;
            if (!get_str(o, "kind", kind) || kind != "exit_lease_admission")
                return false;  // not an admission object; ignore
            sc.saw_any = true;
            std::string scope, seller, client, tid, sig_hex;
            const bool shape = get_str(o, "scope", scope) && scope == "exit_lease"
                && o.contains("v") && o["v"].is_number_integer() && o["v"].get<std::int64_t>() == 2
                && get_str(o, "lock_seller_id", seller) && get_str(o, "client_sesh", client)
                && o.contains("exp") && o["exp"].is_number_integer() && get_str(o, "sig", sig_hex);
            if (!shape || (o.contains("tid") && !get_str(o, "tid", tid)))
            {
                sc.bad = true;
                return false;
            }
            if (seller != this_seller)
            {
                sc.wrong_seller = true;
                return false;
            }
            if (client != remote)
            {
                sc.wrong_client = true;
                return false;
            }
            const auto exp = o["exp"].get<std::int64_t>();
            const auto sig = from_hex<crypto_sign_BYTES>(sig_hex);
            if (!sig)
            {
                sc.bad_sig = true;
                return false;
            }
            const auto msg = admission_message(seller, client, exp, tid);
            if (crypto_sign_verify_detached(
                    sig->data(), reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), issuer.data())
                != 0)
            {
                sc.bad_sig = true;
                return false;
            }
            if (!(exp > now))
            {
                sc.expired = true;
                return false;
            }
            exp_out = exp;
            return true;
        }

        // Visits every object; records the latest valid exp in best_exp (0 = none).
        inline void walk(
            const nlohmann::json& j,
            const PubKey& issuer,
            std::string_view seller,
            std::string_view remote,
            std::int64_t now,
            Scan& sc,
            std::int64_t& best_exp,
            int depth = 0)
        {
            if (depth > 16)
                return;
            if (j.is_object())
            {
                std::int64_t e = 0;
                if (check_record(j, issuer, seller, remote, now, sc, e))
                    best_exp = std::max(best_exp, e);
                for (const auto& [k, v] : j.items())
                    if (v.is_object() || v.is_array())
                        walk(v, issuer, seller, remote, now, sc, best_exp, depth + 1);
            }
            else if (j.is_array())
            {
                for (const auto& v : j)
                    walk(v, issuer, seller, remote, now, sc, best_exp, depth + 1);
            }
        }
    }  // namespace detail

    /// Pure check over the store text (unit-testable).
    inline ExitLeaseAuthResult admission_in_text(
        std::string_view text,
        std::string_view issuer_pubkey_hex,
        std::string_view this_seller,
        std::string_view remote_client,
        std::int64_t now_unix)
    {
        if (issuer_pubkey_hex.empty())
            return {false, "no_issuer"};
        const auto issuer = detail::from_hex<crypto_sign_PUBLICKEYBYTES>(issuer_pubkey_hex);
        if (!issuer)
            return {false, "bad_issuer"};
        if (this_seller.empty() || remote_client.empty())
            return {false, "no_match"};
        auto j = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
        if (j.is_discarded())
            return {false, "bad_file"};
        detail::Scan sc;
        std::int64_t best = 0;
        detail::walk(j, *issuer, this_seller, remote_client, now_unix, sc, best);
        if (best > 0)
            return {true, "admission", best};
        if (sc.bad_sig)
            return {false, "bad_sig"};
        if (sc.expired)
            return {false, "expired"};
        if (sc.bad)
            return {false, "bad_record"};
        if (sc.wrong_client)
            return {false, "wrong_client"};
        if (sc.wrong_seller)
            return {false, "wrong_seller"};
        return {false, "no_match"};
    }

    /// Caches the admission store text, re-reading only when the file's identity changes
    /// (size, mtime and, on POSIX, inode/ns-mtime; the issuer writes by atomic rename, so a
    /// new record always changes the inode). Thread safe.
    class StoreCache
    {
      public:
        static StoreCache& instance()
        {
            static StoreCache c;
            return c;
        }

        std::optional<std::string> read(std::string_view path_sv)
        {
            const std::string path{path_sv};
            const auto id = identify(path);
            std::lock_guard lock{_m};
            if (!id)
            {
                _cache.erase(path);
                return std::nullopt;
            }
            if (auto it = _cache.find(path); it != _cache.end() && it->second.id == *id)
            {
                ++_hits;
                return it->second.text;
            }
            std::ifstream in{path, std::ios::in | std::ios::binary};
            if (!in)
                return std::nullopt;
            std::string text;
            char buf[8192];
            while (in)
            {
                in.read(buf, sizeof(buf));
                if (const auto n = in.gcount(); n > 0)
                    text.append(buf, static_cast<size_t>(n));
                if (text.size() > ADMISSION_MAX_FILE)
                    return std::nullopt;
            }
            ++_loads;
            _cache[path] = Entry{*id, text};
            return text;
        }

        size_t loads() const
        {
            std::lock_guard lock{_m};
            return _loads;
        }
        size_t hits() const
        {
            std::lock_guard lock{_m};
            return _hits;
        }

      private:
        struct Id
        {
            std::uintmax_t size{0};
            std::int64_t mtime_ns{0};
            std::uint64_t ino{0};
            bool operator==(const Id&) const = default;
        };
        struct Entry
        {
            Id id;
            std::string text;
        };

        static std::optional<Id> identify(const std::string& path)
        {
#ifndef _WIN32
            struct stat st{};
            if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
                return std::nullopt;
            return Id{
                static_cast<std::uintmax_t>(st.st_size),
                static_cast<std::int64_t>(st.st_mtim.tv_sec) * 1'000'000'000 + st.st_mtim.tv_nsec,
                static_cast<std::uint64_t>(st.st_ino)};
#else
            std::error_code ec;
            const auto sz = std::filesystem::file_size(path, ec);
            if (ec)
                return std::nullopt;
            const auto mt = std::filesystem::last_write_time(path, ec);
            if (ec)
                return std::nullopt;
            return Id{sz, static_cast<std::int64_t>(mt.time_since_epoch().count()), 0};
#endif
        }

        mutable std::mutex _m;
        std::unordered_map<std::string, Entry> _cache;
        size_t _loads{0}, _hits{0};
    };

    /// Tracks inbound sessions that were admitted by a lease (not whitelist/token) so the
    /// session endpoint can drop them when the lease ends. due(now) returns every key whose
    /// exp has passed, plus all tracked keys once per sweep interval (to catch revocation).
    /// The caller re-validates each due key and calls admitted() (renewed lease), forget()
    /// (allowed some other way, or session gone) or drops the session and forget()s it.
    template <typename Key, typename Hash = std::hash<Key>>
    class LeaseTracker
    {
      public:
        explicit LeaseTracker(std::int64_t sweep_interval_s = 15) : _interval{sweep_interval_s} {}

        void admitted(const Key& k, std::int64_t exp)
        {
            std::lock_guard lock{_m};
            _exp[k] = exp;
        }
        void forget(const Key& k)
        {
            std::lock_guard lock{_m};
            _exp.erase(k);
        }
        std::optional<std::int64_t> exp_of(const Key& k) const
        {
            std::lock_guard lock{_m};
            if (auto it = _exp.find(k); it != _exp.end())
                return it->second;
            return std::nullopt;
        }
        size_t size() const
        {
            std::lock_guard lock{_m};
            return _exp.size();
        }

        std::vector<Key> due(std::int64_t now)
        {
            std::lock_guard lock{_m};
            std::vector<Key> out;
            const bool sweep = now >= _next_sweep;
            if (sweep)
                _next_sweep = now + _interval;
            for (const auto& [k, e] : _exp)
                if (sweep || e <= now)
                    out.push_back(k);
            return out;
        }

      private:
        mutable std::mutex _m;
        std::unordered_map<Key, std::int64_t, Hash> _exp;
        std::int64_t _interval;
        std::int64_t _next_sweep{0};
    };

    /// Order matches SessionEndpoint::validate:
    ///   1. explicit open (auth-type none AND no static lists)  2. static token
    ///   3. whitelist  4. signed lease admission for this seller + remote.
    inline ExitLeaseAuthResult exit_lease_auth_allows(
        bool open_none_empty_lists,
        bool static_token_hit,
        bool whitelist_hit,
        std::string_view admissions_path,
        std::string_view issuer_pubkey_hex,
        std::string_view this_seller,
        std::string_view remote_client,
        std::int64_t now_unix)
    {
        if (open_none_empty_lists)
            return {true, "open_none"};
        if (static_token_hit)
            return {true, "static_token"};
        if (whitelist_hit)
            return {true, "whitelist"};
        if (admissions_path.empty())
            return {false, "no_store"};
        if (issuer_pubkey_hex.empty())
            return {false, "no_issuer"};

        auto text = StoreCache::instance().read(admissions_path);
        if (!text)
            return {false, "bad_file"};
        return admission_in_text(*text, issuer_pubkey_hex, this_seller, remote_client, now_unix);
    }
}  // namespace srouter::auth
