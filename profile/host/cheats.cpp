#include "cheats.hpp"

#include "psprecomp/guest_memory.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace pspweb {
namespace {

std::string trim(const std::string &text) {
    std::size_t first = 0, last = text.size();
    while (first < last && std::isspace(static_cast<unsigned char>(text[first]))) ++first;
    while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1u]))) --last;
    return text.substr(first, last - first);
}

// Strips a trailing '#' comment, but not one inside a quoted label.
std::string strip_comment(const std::string &line) {
    bool quoted = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '"') quoted = !quoted;
        else if (c == '#' && !quoted) return line.substr(0, i);
    }
    return line;
}

std::vector<std::string> split_words(const std::string &line) {
    std::vector<std::string> words;
    std::istringstream in(line);
    std::string word;
    while (in >> word) words.push_back(word);
    return words;
}

// Parses a 0x-prefixed or decimal number into a 32-bit value.
bool parse_u32(const std::string &text, std::uint32_t &out) {
    if (text.empty()) return false;
    char *end = nullptr;
    const unsigned long value = std::strtoul(text.c_str(), &end, 0);
    if (end == text.c_str() || *end != '\0' || value > 0xFFFFFFFFul) return false;
    out = static_cast<std::uint32_t>(value);
    return true;
}

// Recognises the optional width hint that may precede or follow an address:
// "b8"/"byte", "b16"/"half", "b32"/"word", or an explicit byte count for Block.
bool parse_width(const std::string &text, CheatWidth &width) {
    std::string lowered;
    lowered.reserve(text.size());
    for (char c : text) lowered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lowered == "b8" || lowered == "byte" || lowered == "8") { width = CheatWidth::B8; return true; }
    if (lowered == "b16" || lowered == "half" || lowered == "halfword" || lowered == "16") { width = CheatWidth::B16; return true; }
    if (lowered == "b32" || lowered == "word" || lowered == "32") { width = CheatWidth::B32; return true; }
    if (lowered == "block" || lowered == "bytes") { width = CheatWidth::Block; return true; }
    return false;
}

// Unquotes a "..." label.  `words` from `start` onward are joined with single
// spaces first, because split_words broke a quoted label containing spaces.
std::string parse_label(const std::vector<std::string> &words, std::size_t start) {
    std::string joined;
    for (std::size_t i = start; i < words.size(); ++i) {
        if (!joined.empty()) joined.push_back(' ');
        joined += words[i];
    }
    if (joined.size() >= 2u && joined.front() == '"' && joined.back() == '"')
        return joined.substr(1u, joined.size() - 2u);
    return joined;
}

// Parses one entry body, given the already-split words.  `mode` is set by the
// caller from the leading keyword.  Returns false and fills `error` on failure.
bool parse_entry(const std::vector<std::string> &words, std::size_t first, CheatMode mode,
                 CheatEntry &entry, std::string &error, std::size_t line_no) {
    entry.mode = mode;
    auto fail = [&](const std::string &message) {
        std::ostringstream out;
        out << "line " << line_no << ": " << message;
        error = out.str();
        return false;
    };
    if (first >= words.size()) return fail("entry has no operands");

    // Host action:  hle <name> [args...]
    if (words[first] == "hle") {
        if (first + 1u >= words.size()) return fail("hle needs an action name");
        entry.action = words[first + 1u];
        for (std::size_t i = first + 2u; i < words.size(); ++i) {
            std::uint32_t arg = 0u;
            if (!parse_u32(words[i], arg)) return fail("bad hle argument '" + words[i] + "'");
            entry.args.push_back(arg);
        }
        return true;
    }

    // Conditional joker:  cond <test> <caddr> <cval> <addr> <value> [width]
    if (words[first] == "cond" || words[first] == "joker") {
        // Either "cond <caddr> <cval> <addr> <value>" (equal) or
        // "cond <test> <caddr> <cval> <addr> <value>".
        std::size_t at = first + 1u;
        entry.test = CheatTest::Equal;
        if (at < words.size()) {
            std::string t = words[at];
            for (char &c : t) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            const bool named = t == "eq" || t == "ne" || t == "lt" || t == "gt";
            if (named) {
                entry.test = t == "ne" ? CheatTest::NotEqual
                           : t == "lt" ? CheatTest::LessThan
                           : t == "gt" ? CheatTest::GreaterThan
                                       : CheatTest::Equal;
                ++at;
            }
        }
        if (at + 4u > words.size()) return fail("cond needs <test> <caddr> <cval> <addr> <value>");
        if (!parse_u32(words[at], entry.cond_address)) return fail("bad joker address '" + words[at] + "'");
        if (!parse_u32(words[at + 1u], entry.cond_value)) return fail("bad joker value '" + words[at + 1u] + "'");
        if (!parse_u32(words[at + 2u], entry.address)) return fail("bad address '" + words[at + 2u] + "'");
        if (!parse_u32(words[at + 3u], entry.value)) return fail("bad value '" + words[at + 3u] + "'");
        at += 4u;
        // An optional trailing width applies to the poke; the joker reads word-sized
        // unless a second width is given.
        entry.cond_width = CheatWidth::B32;
        if (at < words.size()) {
            CheatWidth w = CheatWidth::B32;
            if (parse_width(words[at], w)) { entry.width = w; entry.cond_width = w; ++at; }
        }
        if (at < words.size()) return fail("too many operands on cond");
        return true;
    }

    // Block:  block <addr> <byte> <byte> ...   (or "block <addr> <count> <b0> ...")
    if (words[first] == "block" || words[first] == "bytes") {
        if (first + 2u > words.size()) return fail("block needs <addr> <byte...>");
        if (!parse_u32(words[first + 1u], entry.address)) return fail("bad block address '" + words[first + 1u] + "'");
        entry.width = CheatWidth::Block;
        for (std::size_t i = first + 2u; i < words.size(); ++i) {
            std::uint32_t byte = 0u;
            if (!parse_u32(words[i], byte) || byte > 0xFFu) return fail("bad block byte '" + words[i] + "'");
            entry.block.push_back(static_cast<std::uint8_t>(byte));
        }
        if (entry.block.empty()) return fail("block has no bytes");
        return true;
    }

    // Plain poke:  <addr> <value> [width]   (width may also precede the value)
    std::size_t at = first;
    if (!parse_u32(words[at], entry.address)) return fail("bad address '" + words[at] + "'");
    ++at;
    entry.width = CheatWidth::B32;
    // Optional width token before the value.
    if (at < words.size()) {
        CheatWidth w = CheatWidth::B32;
        if (parse_width(words[at], w) && at + 1u < words.size()) { entry.width = w; ++at; }
    }
    if (at >= words.size()) return fail("missing value");
    if (!parse_u32(words[at], entry.value)) return fail("bad value '" + words[at] + "'");
    ++at;
    // Optional width token after the value.
    if (at < words.size()) {
        CheatWidth w = CheatWidth::B32;
        if (!parse_width(words[at], w)) return fail("unexpected token '" + words[at] + "'");
        entry.width = w;
        ++at;
    }
    if (at < words.size()) return fail("too many operands");
    return true;
}

const char *mode_keyword(CheatMode mode) {
    switch (mode) {
    case CheatMode::Once: return "once";
    case CheatMode::EveryFrame: return nullptr; // default, no keyword
    case CheatMode::Conditional: return "cond";
    }
    return nullptr;
}

const char *width_keyword(CheatWidth width) {
    switch (width) {
    case CheatWidth::B8: return "b8";
    case CheatWidth::B16: return "b16";
    case CheatWidth::B32: return "b32";
    case CheatWidth::Block: return "block";
    }
    return "b32";
}

} // namespace

CheatLoadResult parse_cheats(const std::string &text) {
    CheatLoadResult result;
    std::istringstream in(text);
    std::string raw;
    std::size_t line_no = 0;
    Cheat *current = nullptr;

    while (std::getline(in, raw)) {
        ++line_no;
        if (!raw.empty() && raw.back() == '\r') raw.pop_back();
        const std::string line = trim(strip_comment(raw));
        if (line.empty()) continue;

        const std::vector<std::string> words = split_words(line);
        if (words.empty()) continue;

        if (words[0] == "cheat") {
            if (words.size() < 2u) {
                result.errors.push_back("line " + std::to_string(line_no) + ": cheat needs an id");
                current = nullptr;
                continue;
            }
            Cheat cheat;
            cheat.id = words[1];
            if (words.size() >= 3u) cheat.name = parse_label(words, 2u);
            if (cheat.name.empty()) cheat.name = cheat.id;
            result.cheats.push_back(std::move(cheat));
            current = &result.cheats.back();
            continue;
        }

        if (current == nullptr) {
            result.errors.push_back("line " + std::to_string(line_no) + ": entry before any 'cheat'");
            continue;
        }

        CheatMode mode = CheatMode::EveryFrame;
        std::size_t first = 0;
        if (words[0] == "once") { mode = CheatMode::Once; first = 1; }
        else if (words[0] == "cond" || words[0] == "joker") { mode = CheatMode::Conditional; first = 0; }
        else if (words[0] == "hle" || words[0] == "block" || words[0] == "bytes") { first = 0; }

        CheatEntry entry;
        std::string error;
        if (!parse_entry(words, first, mode, entry, error, line_no)) {
            result.errors.push_back(error);
            continue;
        }
        current->entries.push_back(std::move(entry));
    }

    // Drop cheats that parsed to nothing, so an empty stub never reaches the UI.
    result.cheats.erase(std::remove_if(result.cheats.begin(), result.cheats.end(),
                                       [](const Cheat &c) { return c.entries.empty(); }),
                        result.cheats.end());
    return result;
}

std::string format_cheats(const std::vector<Cheat> &cheats) {
    std::ostringstream out;
    out << "# PSP Web Recomp cheat file.  See docs/cheats.md.\n";
    for (const Cheat &cheat : cheats) {
        out << "\ncheat " << cheat.id << " \"" << cheat.name << "\"\n";
        for (const CheatEntry &e : cheat.entries) {
            if (!e.action.empty()) {
                out << "  hle " << e.action;
                for (std::uint32_t arg : e.args) {
                    char buf[16];
                    std::snprintf(buf, sizeof buf, " 0x%08X", arg);
                    out << buf;
                }
                out << '\n';
                continue;
            }
            char hex[64];
            if (e.mode == CheatMode::Conditional) {
                const char *test = e.test == CheatTest::NotEqual ? "ne"
                                 : e.test == CheatTest::LessThan ? "lt"
                                 : e.test == CheatTest::GreaterThan ? "gt" : "eq";
                std::snprintf(hex, sizeof hex, "  cond %s 0x%08X 0x%08X 0x%08X 0x%08X %s\n", test,
                              e.cond_address, e.cond_value, e.address, e.value, width_keyword(e.width));
                out << hex;
                continue;
            }
            const char *keyword = mode_keyword(e.mode);
            if (e.width == CheatWidth::Block) {
                out << "  block 0x" << std::hex << std::uppercase << e.address << std::dec;
                for (std::uint8_t b : e.block) out << " 0x" << std::hex << std::uppercase << static_cast<unsigned>(b) << std::dec;
                out << '\n';
                continue;
            }
            if (keyword) out << "  " << keyword;
            std::snprintf(hex, sizeof hex, " 0x%08X 0x%08X %s\n", e.address, e.value, width_keyword(e.width));
            out << hex;
        }
    }
    return out.str();
}

// ---------------------------------------------------------------------------

void CheatEngine::register_action(std::string name, Action action) {
    actions_.insert_or_assign(std::move(name), std::move(action));
}

bool CheatEngine::has_action(const std::string &name) const {
    return actions_.find(name) != actions_.end();
}

void CheatEngine::set_cheats(CheatLoadResult loaded) {
    // Preserve the enabled flag across a reload by id.
    for (Cheat &cheat : loaded.cheats) {
        for (const Cheat &old : cheats_) {
            if (old.id == cheat.id) { cheat.enabled = old.enabled; break; }
        }
    }
    cheats_ = std::move(loaded.cheats);
    errors_ = std::move(loaded.errors);
}

bool CheatEngine::set_enabled(const std::string &id, bool enabled) {
    for (Cheat &cheat : cheats_) {
        if (cheat.id == id) {
            cheat.enabled = enabled;
            if (enabled) for (CheatEntry &e : cheat.entries) e.applied_once = false;
            return true;
        }
    }
    return false;
}

void CheatEngine::set_all_enabled(bool enabled) {
    for (Cheat &cheat : cheats_) {
        cheat.enabled = enabled;
        if (enabled) for (CheatEntry &e : cheat.entries) e.applied_once = false;
    }
}

bool CheatEngine::any_enabled() const noexcept {
    for (const Cheat &cheat : cheats_) if (cheat.enabled) return true;
    return false;
}

void CheatEngine::reset_once_flags() {
    for (Cheat &cheat : cheats_) for (CheatEntry &e : cheat.entries) e.applied_once = false;
}

void CheatEngine::apply_entry(CheatEntry &entry) {
    if (entry.action.empty()) {
        if (memory_ == nullptr) return;
        switch (entry.width) {
        case CheatWidth::B8: memory_->store8(entry.address, static_cast<std::uint8_t>(entry.value & 0xFFu)); break;
        case CheatWidth::B16: memory_->store16(entry.address, static_cast<std::uint16_t>(entry.value & 0xFFFFu)); break;
        case CheatWidth::B32: memory_->store32(entry.address, entry.value); break;
        case CheatWidth::Block:
            if (!entry.block.empty()) memory_->copy_in(entry.address, entry.block);
            break;
        }
        return;
    }
    const auto it = actions_.find(entry.action);
    if (it != actions_.end()) it->second(entry);
}

void CheatEngine::apply_frame() {
    for (Cheat &cheat : cheats_) {
        if (!cheat.enabled) continue;
        for (CheatEntry &entry : cheat.entries) {
            if (entry.mode == CheatMode::Once && entry.applied_once) continue;
            if (entry.mode == CheatMode::Conditional) {
                if (memory_ == nullptr) continue;
                const std::uint32_t observed = entry.cond_width == CheatWidth::B8 ? memory_->load8(entry.cond_address)
                                              : entry.cond_width == CheatWidth::B16 ? memory_->load16(entry.cond_address)
                                                                                    : memory_->load32(entry.cond_address);
                const bool match = entry.test == CheatTest::Equal ? observed == entry.cond_value
                                 : entry.test == CheatTest::NotEqual ? observed != entry.cond_value
                                 : entry.test == CheatTest::LessThan ? observed < entry.cond_value
                                                                     : observed > entry.cond_value;
                if (!match) continue;
            }
            apply_entry(entry);
            if (entry.mode == CheatMode::Once) entry.applied_once = true;
        }
    }
}

} // namespace pspweb
