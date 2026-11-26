// SPDX-License-Identifier: MIT
#include "prahari/sbi.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <vector>

namespace prahari::sbi {
namespace {

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

bool all_digits(std::string_view s) {
    return !s.empty() && std::ranges::all_of(s, is_digit);
}

std::vector<std::string_view> split(std::string_view s, char sep) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    while (start <= s.size()) {
        const auto pos = s.find(sep, start);
        if (pos == std::string_view::npos) {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

bool is_service_name(std::string_view s) {
    if (s.size() < 2 || s.size() > kMaxService || s[0] != 'n') {
        return false;
    }
    return std::ranges::all_of(
        s, [](char c) { return (c >= 'a' && c <= 'z') || is_digit(c) || c == '-'; });
}

bool is_version(std::string_view s) {
    return s.size() >= 2 && s[0] == 'v' && all_digits(s.substr(1));
}

struct Op {
    std::string_view service;
    std::string_view method;
    std::string_view pattern;  // segments after "/<service>/<version>/", '*' = any one
    std::string_view name;
};

// TS 29.510 (NRF), 29.509 (AUSF), 29.503 (UDM), 29.504/505 (UDR), 29.502 (SMF),
// 29.518 (AMF), 29.507/512 (PCF), 29.521 (BSF), 29.531 (NSSF).
constexpr std::array kOps{
    Op{"nnrf-nfm", "PUT", "nf-instances/*", "NFRegister"},
    Op{"nnrf-nfm", "PATCH", "nf-instances/*", "NFUpdate"},
    Op{"nnrf-nfm", "DELETE", "nf-instances/*", "NFDeregister"},
    Op{"nnrf-nfm", "GET", "nf-instances/*", "NFProfileRetrieval"},
    Op{"nnrf-nfm", "GET", "nf-instances", "NFListRetrieval"},
    Op{"nnrf-nfm", "POST", "subscriptions", "NFStatusSubscribe"},
    Op{"nnrf-nfm", "PATCH", "subscriptions/*", "NFStatusSubscribeUpdate"},
    Op{"nnrf-nfm", "DELETE", "subscriptions/*", "NFStatusUnsubscribe"},
    Op{"nnrf-nfm", "POST", "nf-status-notify", "NFStatusNotify"},
    Op{"nnrf-disc", "GET", "nf-instances", "NFDiscover"},
    Op{"nausf-auth", "POST", "ue-authentications", "Authenticate"},
    Op{"nausf-auth", "PUT", "ue-authentications/*/5g-aka-confirmation", "AuthenticateConfirm"},
    Op{"nausf-auth", "DELETE", "ue-authentications/*/5g-aka-confirmation", "AuthenticateDelete"},
    Op{"nudm-ueau", "POST", "*/security-information/generate-auth-data", "GenerateAuthData"},
    Op{"nudm-ueau", "POST", "*/auth-events", "ConfirmAuth"},
    Op{"nudm-uecm", "PUT", "*/registrations/amf-3gpp-access", "Amf3GppAccessRegistration"},
    Op{"nudm-uecm", "PATCH", "*/registrations/amf-3gpp-access", "Amf3GppAccessRegistrationUpdate"},
    Op{"nudm-uecm", "PUT", "*/registrations/smf-registrations/*", "SmfRegistration"},
    Op{"nudm-uecm", "DELETE", "*/registrations/smf-registrations/*", "SmfDeregistration"},
    Op{"nudm-sdm", "GET", "*/am-data", "GetAmData"},
    Op{"nudm-sdm", "GET", "*/sm-data", "GetSmData"},
    Op{"nudm-sdm", "GET", "*/smf-select-data", "GetSmfSelectData"},
    Op{"nudm-sdm", "GET", "*/ue-context-in-smf-data", "GetUeContextInSmfData"},
    Op{"nudm-sdm", "GET", "*/nssai", "GetNssai"},
    Op{"nudm-sdm", "GET", "*", "GetDataSets"},
    Op{"nudm-sdm", "POST", "*/sdm-subscriptions", "SdmSubscribe"},
    Op{"nudm-sdm", "DELETE", "*/sdm-subscriptions/*", "SdmUnsubscribe"},
    Op{"nsmf-pdusession", "POST", "sm-contexts", "CreateSMContext"},
    Op{"nsmf-pdusession", "POST", "sm-contexts/*/modify", "UpdateSMContext"},
    Op{"nsmf-pdusession", "POST", "sm-contexts/*/release", "ReleaseSMContext"},
    Op{"nsmf-pdusession", "POST", "sm-contexts/*/retrieve", "RetrieveSMContext"},
    Op{"namf-comm", "POST", "ue-contexts/*/n1-n2-messages", "N1N2MessageTransfer"},
    Op{"namf-comm", "PUT", "ue-contexts/*", "CreateUEContext"},
    Op{"namf-comm", "POST", "ue-contexts/*/release", "ReleaseUEContext"},
    Op{"namf-comm", "POST", "ue-contexts/*/transfer", "UEContextTransfer"},
    Op{"namf-callback", "POST", "*/sm-context-status/*", "SMContextStatusNotify"},
    Op{"npcf-am-policy-control", "POST", "policies", "AMPolicyCreate"},
    Op{"npcf-am-policy-control", "POST", "policies/*/update", "AMPolicyUpdate"},
    Op{"npcf-am-policy-control", "DELETE", "policies/*", "AMPolicyDelete"},
    Op{"npcf-smpolicycontrol", "POST", "sm-policies", "SMPolicyCreate"},
    Op{"npcf-smpolicycontrol", "POST", "sm-policies/*/update", "SMPolicyUpdate"},
    Op{"npcf-smpolicycontrol", "POST", "sm-policies/*/delete", "SMPolicyDelete"},
    Op{"nbsf-management", "POST", "pcfBindings", "PcfBindingRegister"},
    Op{"nbsf-management", "DELETE", "pcfBindings/*", "PcfBindingDeregister"},
    Op{"nnssf-nsselection", "GET", "network-slice-information", "NSSelectionGet"},
};

bool matches(const std::vector<std::string_view>& segs, std::size_t from,
             std::string_view pattern) {
    const auto pat = split(pattern, '/');
    if (segs.size() - from != pat.size()) {
        return false;
    }
    for (std::size_t i = 0; i < pat.size(); ++i) {
        if (pat[i] != "*" && pat[i] != segs[from + i]) {
            return false;
        }
    }
    return true;
}

std::optional<std::string> imsi_digits(std::string_view s) {
    std::size_t n = 0;
    while (n < s.size() && n < 16 && is_digit(s[n])) {
        ++n;
    }
    if (n < 5 || n > 15) {
        return std::nullopt;
    }
    return std::string{s.substr(0, n)};
}

// Length of a SUCI token: letters, digits and '-'.
std::size_t token_len(std::string_view s) {
    std::size_t n = 0;
    while (n < s.size() && n < 128 &&
           (is_digit(s[n]) || s[n] == '-' || (s[n] >= 'a' && s[n] <= 'z') ||
            (s[n] >= 'A' && s[n] <= 'Z'))) {
        ++n;
    }
    return n;
}

std::string_view skip_json_ws(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) {
        ++i;
    }
    return s.substr(i);
}

// Position after `"key"` and a following ':' (JSON), or npos.
std::size_t value_after_key(std::string_view body, std::string_view quoted_key, std::size_t from,
                            std::string_view& value) {
    while (true) {
        const auto k = body.find(quoted_key, from);
        if (k == std::string_view::npos) {
            return std::string_view::npos;
        }
        auto rest = skip_json_ws(body.substr(k + quoted_key.size()));
        if (!rest.empty() && rest[0] == ':') {
            value = skip_json_ws(rest.substr(1));
            return k;
        }
        from = k + quoted_key.size();
    }
}

}  // namespace

std::optional<std::string> imsi_from_identity(std::string_view id) {
    if (id.starts_with("imsi-")) {
        auto d = imsi_digits(id.substr(5));
        if (d && d->size() == id.size() - 5) {
            return d;
        }
        return std::nullopt;
    }
    if (id.starts_with("suci-")) {
        // suci-<type>-<mcc>-<mnc>-<routing>-<scheme>-<hnpki>-<output> (TS 29.503 5.4.3)
        const auto f = split(id.substr(5), '-');
        if (f.size() != 7 || f[0] != "0" || f[4] != "0") {
            return std::nullopt;  // not IMSI-based, or a real protection scheme
        }
        if (!all_digits(f[1]) || f[1].size() != 3 || !all_digits(f[2]) || f[2].size() < 2 ||
            f[2].size() > 3 || !all_digits(f[6])) {
            return std::nullopt;
        }
        std::string imsi{f[1]};
        imsi += f[2];
        imsi += f[6];
        if (imsi.size() < 5 || imsi.size() > 15) {
            return std::nullopt;
        }
        return imsi;
    }
    return std::nullopt;
}

Target parse_target(std::string_view raw) {
    Target t;
    const auto q = raw.find_first_of("?#");
    const auto path = raw.substr(0, q);
    auto segs = split(path, '/');
    std::string out;
    out.reserve(path.size());
    for (std::size_t i = 0; i < segs.size(); ++i) {
        const auto seg = segs[i];
        std::string_view clean = seg;
        if (seg.starts_with("imsi-")) {
            if (!t.imsi) {
                t.imsi = imsi_from_identity(seg);
            }
            clean = "{supi}";
        } else if (seg.starts_with("suci-")) {
            if (!t.imsi) {
                t.imsi = imsi_from_identity(seg);
            }
            clean = "{suci}";
        } else if (seg.starts_with("msisdn-") || seg.starts_with("extid-") ||
                   seg.starts_with("gpsi-")) {
            clean = "{gpsi}";
        } else if (seg.starts_with("nai-")) {
            clean = "{nai}";
        }
        if (clean != seg) {
            t.had_identity = true;
        }
        if (i > 0) {
            out += '/';
        }
        out += clean;
    }
    if (out.size() > kMaxPath) {
        const auto cut = out.rfind('/', kMaxPath);
        out.resize(cut == std::string::npos || cut == 0 ? kMaxPath : cut);
    }
    t.path = std::move(out);
    if (segs.size() >= 3 && segs[0].empty() && is_service_name(segs[1]) && is_version(segs[2])) {
        t.service = segs[1];
    }
    return t;
}

std::string operation_name(std::string_view method, const Target& t) {
    if (!t.service.empty()) {
        const auto segs = split(t.path, '/');  // "", service, version, ...
        for (const auto& op : kOps) {
            if (op.service == t.service && op.method == method && matches(segs, 3, op.pattern)) {
                return std::string{op.name};
            }
        }
        if (t.service == "nudr-dr") {
            // TS 29.504: CRUD on data resources; the path says which.
            if (method == "GET") {
                return "DRQuery";
            }
            if (method == "PUT" || method == "POST") {
                return "DRCreate";
            }
            if (method == "PATCH") {
                return "DRUpdate";
            }
            if (method == "DELETE") {
                return "DRDelete";
            }
        }
    }
    std::string name{method.empty() ? std::string_view{"UNKNOWN"} : method.substr(0, 16)};
    name += ' ';
    name += t.service.empty() ? std::string_view{"non-sbi"} : std::string_view{t.service};
    return name;
}

std::optional<std::string> find_imsi(std::string_view body) {
    std::size_t from = 0;
    while (from < body.size()) {
        const auto a = body.find("imsi-", from);
        const auto b = body.find("suci-", from);
        const auto pos = std::min(a, b);
        if (pos == std::string_view::npos) {
            return std::nullopt;
        }
        const auto tok = body.substr(pos, token_len(body.substr(pos)));
        if (auto imsi = imsi_from_identity(tok)) {
            return imsi;
        }
        from = pos + 5;
    }
    return std::nullopt;
}

std::optional<std::uint8_t> find_pdu_session_id(std::string_view body) {
    std::string_view v;
    if (value_after_key(body, "\"pduSessionId\"", 0, v) == std::string_view::npos) {
        return std::nullopt;
    }
    unsigned n = 0;
    std::size_t i = 0;
    while (i < v.size() && i < 3 && is_digit(v[i])) {
        n = n * 10 + static_cast<unsigned>(v[i] - '0');
        ++i;
    }
    if (i == 0 || n > 255 || (i < v.size() && is_digit(v[i]))) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(n);
}

std::optional<std::string> find_problem_cause(std::string_view body) {
    std::string_view v;
    std::size_t from = 0;
    while (true) {
        const auto k = value_after_key(body, "\"cause\"", from, v);
        if (k == std::string_view::npos) {
            return std::nullopt;
        }
        from = k + 7;
        if (v.empty() || v[0] != '"') {
            continue;
        }
        const auto end = v.find('"', 1);
        if (end == std::string_view::npos) {
            return std::nullopt;
        }
        const auto cause = v.substr(1, end - 1);
        bool ok = !cause.empty() && cause.size() <= 64;
        for (const char c : cause) {
            ok = ok && ((c >= 'A' && c <= 'Z') || is_digit(c) || c == '_');
        }
        if (ok) {
            return std::string{cause};
        }
    }
}

}  // namespace prahari::sbi
