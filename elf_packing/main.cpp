#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // read
#include <string.h>

#define CALL_ADDRESS_INDEX_IN_SHELLCODE 35
#define SIZE_TO_XOR_OFFSET 10
#define PACKED_FILE_PATH_TEMPLATE "%s_packed"

unsigned char shellcode[] = {
0x48, 0xC7, 0xC6, 0xA0, 0x09, 0x40, 0x00, // mov rsi, 0x4009a0 , 0-6
0x48, 0xC7, 0xC1, 0xC8, 0x09, 0x00, 0x00, // mov rcx,0x9c8 , 7-13
0x48, 0x0F, 0xB6, 0x06, // movzx  rax,BYTE PTR [rsi] ; 14-17
0x48,0x83 ,  0xF0, 0x33 , // xor rax, 0x33 , 18-21
0x88, 0x06, // mov    BYTE PTR [rsi],al ; 22-23
0x48, 0xFF, 0xC6, //inc rsi ; 24-26
0x48, 0xFF, 0xC9, // dec rcx ; 27-29
0x75, 0xee, // jne -15 ; 30-31
0x48, 0xC7, 0xC0, 0x78, 0x56, 0x34, 0x12, // mov rax, 0x12345678 ; 32-38
0xFF, 0xD0, // call rax  ; 39-40
0xC3 // ret ; 41
};


typedef struct space_details {
	uint64_t offset;
	size_t  size;
}SpaceDetails, *PSpaceDetails;

union addr {
	uint64_t as_num;
	unsigned char as_bytes[8];
};

size_t get_file_size(char * path)
{
	struct stat st;
	stat(path, &st);
	return st.st_size;
}

unsigned char * read_file(char * path)
{
	int fd = 0;
	if ((fd = open(path, O_RDONLY)) < 0)
	{
		perror("open(filepath, O_RDONLY) ");
		return NULL;
	}

	size_t file_size = get_file_size(path);
	unsigned char * file_buffer;
	if ((file_buffer = (unsigned char *)calloc(file_size, sizeof(unsigned char))) < 0)
	{
		perror("calloc ");
		return NULL;
	}
	unsigned char * ptr = file_buffer;
	int bytes_read = 0, sum_bytes = 0;
	while (sum_bytes < file_size && (bytes_read = read(fd, ptr, file_size)) > 0) 
	{
		ptr += bytes_read;
		sum_bytes += bytes_read;
	}
	return file_buffer;
}

Elf64_Shdr * get_section_header_in_index(Elf64_Ehdr * elf_header, int index)
{
	if (index >= elf_header->e_shnum)
		return NULL;

	Elf64_Shdr * section_header = (Elf64_Shdr * )((uint64_t)elf_header->e_shoff + (uint64_t)elf_header);	
	return &(section_header[index]);
}

Elf64_Shdr * get_section_header_by_type(Elf64_Ehdr * elf_header, uint32_t section_type)
{
	Elf64_Shdr * section_header_arrary = get_section_header_in_index(elf_header, 0);
	Elf64_Shdr * section_header_for_string_table = &(section_header_arrary[elf_header->e_shstrndx]);
	char * string_table = (char *)((uint64_t)elf_header + (uint64_t)section_header_for_string_table->sh_offset);

	int index = 0;
	for (index = 0; index < elf_header->e_shnum && section_header_arrary[index].sh_type != SHT_SYMTAB; index++)
		;

	printf("index: %d\n", index - 1);
	return &(section_header_arrary[index]);
}

Elf64_Shdr * get_section_header_by_name(Elf64_Ehdr * elf_header, char * name)
{
	Elf64_Shdr * section_header_arrary = get_section_header_in_index(elf_header, 0);
	Elf64_Shdr * section_header_for_string_table = &(section_header_arrary[elf_header->e_shstrndx]);
	char * string_table = (char *)((uint64_t)elf_header + (uint64_t)section_header_for_string_table->sh_offset);

	int index = 0;
	char * current_name;

	current_name = string_table + section_header_arrary[index].sh_name;
	for (index = 0; index < elf_header->e_shnum && strcmp(current_name, name) != 0; index++)
		current_name = string_table + section_header_arrary[index].sh_name;

	printf("index: %d\n", index - 1);
	return &(section_header_arrary[index - 1]);
}

Elf64_Phdr * get_array_of_program_headers(Elf64_Ehdr * elf_header)
{
	return (Elf64_Phdr *)((uint64_t)elf_header->e_phoff + (uint64_t)elf_header);
}

Elf64_Phdr * get_load_program_header_by_count(Elf64_Phdr * program_header_array,
	int array_size, int index_to_get)
{
	int index = 0, load_count = 0;
	for (index = 0; index < array_size && load_count < 2; index++)
	{
		if (PT_LOAD == program_header_array[index].p_type)
			if (load_count++ == index_to_get)
				return &(program_header_array[index]); 			
	}
	return NULL;
}

bool space_between_load_program_headers(Elf64_Ehdr * pelf_header, PSpaceDetails space_details_to_ret) 
{
	Elf64_Phdr * program_header_array = get_array_of_program_headers(pelf_header);

	Elf64_Phdr * first_load_program_header = get_load_program_header_by_count(program_header_array,
		pelf_header->e_phnum, 0);
	Elf64_Phdr * second_load_program_header = get_load_program_header_by_count(program_header_array,
		pelf_header->e_phnum, 1);

	uint64_t end_of_first = (uint64_t)first_load_program_header->p_offset + (uint64_t)first_load_program_header->p_filesz;
	uint64_t size_of_empty_space = (uint64_t)second_load_program_header->p_offset - end_of_first;

	space_details_to_ret->offset = end_of_first;
	space_details_to_ret->size = size_of_empty_space;
	return true;
}

uint64_t get_base_address(Elf64_Ehdr * elf_header)
{
	Elf64_Phdr * first_load_program_header = get_load_program_header_by_count(get_array_of_program_headers(elf_header),
		elf_header->e_phnum, 0);

	return first_load_program_header->p_vaddr;
}


int set_old_entrypoint_addresses_in_shellcode(Elf64_Ehdr * elf_header, unsigned char * shellcode)
{
	addr base_address;
	base_address.as_num = elf_header->e_entry;
	size_t size_of_array = sizeof(base_address.as_bytes) / 2;
	for (size_t i = 0; i < size_of_array; i++)
	{

		shellcode[CALL_ADDRESS_INDEX_IN_SHELLCODE + i] = base_address.as_bytes[i];
		printf("0x%x\n", base_address.as_bytes[i]);
	}
	printf("entry in shellcode: 0x%08X\n", shellcode[CALL_ADDRESS_INDEX_IN_SHELLCODE]);



	return 0;
}

bool set_perm_to_program_header(Elf64_Phdr * program_header, int flags)
{
	program_header->p_flags = flags;
	return true;
}

bool set_rwx_perm_to_program_header(Elf64_Phdr * program_header)
{
	return set_perm_to_program_header(program_header, 0x7); // PF_X | PF_W | PF_R
}

bool get_packed_file_path(char * path, char * packed_file_path)
{
	size_t size_of_path= strlen(path) + strlen(PACKED_FILE_PATH_TEMPLATE) - 2 + 1;
	snprintf(packed_file_path, size_of_path, PACKED_FILE_PATH_TEMPLATE, path);
	return true;
}

unsigned char * get_section(Elf64_Ehdr * elf_header, Elf64_Shdr * section)
{
	return (unsigned char *)((uint64_t)section->sh_offset + (uint64_t)elf_header);
}

bool encrypt_buffer(unsigned char * buffer, size_t size_of_buffer, int key)
{
	int char_index_to_xor = 0;
	for (char_index_to_xor = 0; char_index_to_xor < size_of_buffer; char_index_to_xor++)
		buffer[char_index_to_xor] ^= key;

	return true;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("[-] Missing file path to pack.\n");
		return 1;
	}

  	char * filepath = argv[1];
	unsigned char * file_buffer = read_file(filepath);
	if (NULL == file_buffer)
	{
		perror("file_buffer "); 
		return 1;
	}

	Elf64_Ehdr * elf_header = (Elf64_Ehdr * )file_buffer;
	if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0)
	{
		printf("elf magic error.\n");
		return 1;
	}

	Elf64_Shdr * text_section = get_section_header_by_name(elf_header, ".text");
	unsigned char * buffer_to_xor = get_section(elf_header, text_section);

	encrypt_buffer(buffer_to_xor, text_section->sh_size, 0x33);

	SpaceDetails empty_space_details;
	space_between_load_program_headers(elf_header, &empty_space_details);
	
	Elf64_Phdr * first_load_program_header = get_load_program_header_by_count(get_array_of_program_headers(elf_header), elf_header->e_phentsize, 0);
	set_rwx_perm_to_program_header(first_load_program_header);

	unsigned char * shellcode_in_file_buffer = (unsigned char *)((uint64_t)file_buffer + empty_space_details.offset);

	if (sizeof(shellcode) >= empty_space_details.size)
		printf("size of shellcode: %d, empty_space_size: %d\n", sizeof(shellcode), empty_space_details.size);
	else
		memcpy(shellcode_in_file_buffer, shellcode, sizeof(shellcode));

	
	set_old_entrypoint_addresses_in_shellcode(elf_header, shellcode_in_file_buffer);

	addr text_section_size;
	text_section_size.as_num = text_section->sh_size;
	for (int i = 0; i < sizeof(text_section_size.as_bytes) / 2; i++)
	{
		shellcode_in_file_buffer[SIZE_TO_XOR_OFFSET + i] = text_section_size.as_bytes[i];
	}

	uint64_t base_address = get_base_address(elf_header);
	elf_header->e_entry = base_address + empty_space_details.offset;

	//Elf64_Shdr * n = get_section_header_by_type(elf_header, SHT_SYMTAB);

	//Elf64_Sym * symbol_table = (Elf64_Sym * )((uint64_t)(n->sh_offset) + (uint64_t)(elf_header));
	//int symbol_count = n->sh_size / sizeof(Elf64_Sym);
	//printf("%d symbols.\n", symbol_count);

	//for (int z = 0; z < symbol_count; z++)
	//{
	//	printf("0x%08X \n", symbol_table[z].st_value);
	//	printf("0x%02x ", ELF64_ST_BIND(symbol_table[z].st_info));
	//	printf("0x%02x ", ELF32_ST_TYPE(symbol_table[i].st_info));
	//	printf("%s\n", (str_tbl + symbol_table[i].st_name));
	//}

	int new_fd;
	if ((new_fd = open("/home/shahar/projects/arping/bin/x64/Release/arping1.out", O_CREAT| O_WRONLY)) < 0)
	{
		perror("open arping1");
		return 1;
	}
	
	int bytes_written = write(new_fd, file_buffer, get_file_size(filepath));
	printf("bytes_written %d\n", bytes_written);
	return 0;
}