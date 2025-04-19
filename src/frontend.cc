#include <capstone/capstone.h>
#include <elfio/elfio.hpp>
#include <iostream>
#include <span>
#include <unordered_set>
#include <memory>
#include <stdexcept>

// RAII wrapper for Capstone instructions
class InstructionSet {
public:
    InstructionSet(cs_insn* insn, size_t count) : m_insn(insn), m_count(count) {}
    ~InstructionSet() { if (m_insn) cs_free(m_insn, m_count); }
    
    cs_insn* get() const { return m_insn; }
    size_t count() const { return m_count; }
    
    // Prevent copying
    InstructionSet(const InstructionSet&) = delete;
    InstructionSet& operator=(const InstructionSet&) = delete;
    
private:
    cs_insn* m_insn;
    size_t m_count;
};

class Capstone {
public:
    class Builder {
    public:
        Builder& setArch(cs_arch arch) { m_arch = arch; return *this; }
        Builder& setMode(cs_mode mode) { m_mode = mode; return *this; }
        
        Capstone build() const {
            return Capstone(m_arch, m_mode);
        }
    private:
        cs_arch m_arch = CS_ARCH_X86;
        cs_mode m_mode = CS_MODE_64;
    };

    // Allow moving
    Capstone(Capstone&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = 0;
    }
    
    ~Capstone() {
        if (m_handle) {
            cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_OFF);
            cs_close(&m_handle);
        }
    }

    std::unique_ptr<InstructionSet> disasm(std::span<const uint8_t> buffer, size_t offset) const {
        cs_insn* insn;
        size_t count = cs_disasm(m_handle, buffer.data(), buffer.size(), offset, 0, &insn);
        if (count == 0) return nullptr;
        return std::make_unique<InstructionSet>(insn, count);
    }

    std::string_view name_of_group(int id) const {
        return cs_group_name(m_handle, id);
    }

    std::string_view get_last_error() const {
        return cs_strerror(cs_errno(m_handle));
    }

private:
    explicit Capstone(cs_arch arch, cs_mode mode) {
        if (cs_open(arch, mode, &m_handle) != CS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Capstone");
        }
        cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(m_handle, CS_OPT_SKIPDATA, CS_OPT_OFF);
    }

    csh m_handle;
};

// Constants
constexpr int MIN_VALID_GROUP_ID = 128;

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <ELF filename>\n";
        return 1;
    }

    try {
        ELFIO::elfio reader;
        if (!reader.load(argv[1])) {
            throw std::runtime_error("Failed to load ELF file");
        }

        auto section = reader.sections[".text"];
        if (!section) {
            throw std::runtime_error("Failed to find .text section");
        }

        auto buffer = std::span{
            reinterpret_cast<const uint8_t*>(section->get_data()),
            section->get_size()
        };

        std::unordered_set<int> groups;
        auto capstone = Capstone::Builder()
            .setArch(CS_ARCH_X86)
            .setMode(CS_MODE_64)
            .build();

        auto insn_set = capstone.disasm(buffer, 0x1000);
        if (!insn_set) {
            throw std::runtime_error(std::string("Failed to disassemble code: ") + 
                                   std::string(capstone.get_last_error()));
        }

        // Process instructions
        for (size_t j = 0; j < insn_set->count(); j++) {
            const auto& insn = insn_set->get()[j];
            for (int i = 0; i < insn.detail->groups_count; ++i) {
                groups.insert(insn.detail->groups[i]);
            }
        }

        // Output results
        std::cout << "The following instruction sets were used:\n";
        for (int gid : groups) {
            if (gid > MIN_VALID_GROUP_ID) {
                std::cout << "\t" << capstone.name_of_group(gid) << '\n';
            }
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
