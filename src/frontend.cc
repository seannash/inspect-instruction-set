#include <capstone/capstone.h>

#include <elfio/elfio.hpp>
#include <iostream>
#include <span>
#include <unordered_set>

class Capstone {
 public:
  class Builder {
   public:
    Capstone build() { return {}; }
  };

  Capstone();
  ~Capstone();

  int disasm(std::span<const uint8_t> buffer, size_t offset, cs_insn** insn);

  std::string_view name_of_group(int id);

  std::string_view get_last_error();

 private:
  csh m_handle;

 private:
  Capstone(const Capstone&) = delete;
  Capstone(Capstone&&) = delete;
  Capstone operator=(Capstone) = delete;
};

std::string_view Capstone::name_of_group(int id) {
  return {cs_group_name(m_handle, id)};
}

std::string_view Capstone::get_last_error() {
  return {cs_strerror(cs_errno(m_handle))};
}

int Capstone::disasm(std::span<const uint8_t> buffer, size_t offset,
                     cs_insn** insn) {
  return cs_disasm(m_handle, reinterpret_cast<const uint8_t*>(buffer.data()),
                   buffer.size(), offset, 0, insn);
}

Capstone::Capstone() {
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &m_handle) != CS_ERR_OK) {
    throw std::runtime_error("Failed to initialize Capstone");
  }
  cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(m_handle, CS_OPT_SKIPDATA, CS_OPT_OFF);
}

Capstone::~Capstone() {
  cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_OFF);
  cs_close(&m_handle);
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <ELF filename>\n";
    return 1;
  }

  const char* filename = argv[1];

  ELFIO::elfio reader;
  reader.load(filename);

  auto section = reader.sections[".text"];
  auto buffer = std::span{(uint8_t*)section->get_data(),
                          (uint8_t*)section->get_data() + section->get_size()};
  cs_insn* insn;

  std::unordered_set<int> groups{};

  Capstone capstone = Capstone::Builder().build();

  auto count = capstone.disasm(buffer, 0x1000, &insn);
  if (count > 0) {
    size_t j;
    for (j = 0; j < count; j++) {
      for (int i = 0; i < insn[j].detail->groups_count; ++i) {
        int id = insn[j].detail->groups[i];
        groups.insert(id);
      }
    }
    cs_free(insn, count);
  } else {
    std::cout << "Failed to disassemble given code! "
              << capstone.get_last_error() << '\n';
  }

  std::cout << "The following instruction sets were used:\n";
  for (int gid : groups) {
    if (gid > 128) std::cout << "\t" << capstone.name_of_group(gid) << '\n';
  }

  return 0;
}
