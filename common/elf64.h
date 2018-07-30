#define EI_NIDENT 16

typedef struct
{
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} elf64_ehdr_t;

#define ELFMAG "\177ELF"

#define ET_NONE 0
#define ET_REL 1
#define ET_EXEC 2
#define ET_DYN 3

typedef struct
{
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
} elf64_phdr_t;

#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_SHLIB 5
#define PT_PHDR 6

#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

typedef struct
{
  uint64_t a_type;
  uint64_t a_val;
} elf64_auxv_t;

#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_BASE 7
#define AT_ENTRY 9
#define AT_EXECFN 31
#define AT_SYSINFO_EHDR 33

typedef struct
{
  int64_t d_tag;
  uint64_t d_val;
} elf64_dyn_t;

#define DT_NULL 0
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6

typedef struct
{
  uint32_t st_name;
  unsigned char st_info;
  unsigned char st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
} elf64_sym_t;

#define ELF64_ST_BIND(val) (((unsigned char) (val)) >> 4)
#define ELF64_ST_TYPE(val) ((val) & 0xf)
