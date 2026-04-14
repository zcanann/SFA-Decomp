#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/alloc.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/buffer_io.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/file_io.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/critical_regions.h"

void* malloc(size_t size);

inline void __convert_from_newlines(unsigned char* p, size_t* n) { }

void __prep_buffer(FILE* file)
{
	file->buffer_ptr = file->buffer;
	file->buffer_length = file->buffer_size;
	file->buffer_length -= file->position & file->buffer_alignment;
	file->buffer_position = file->position;
}

int __load_buffer(FILE* file, size_t* bytes_loaded, int mode)
{
	int ioresult;
	unsigned char* buffer_start;

	__prep_buffer(file);

	if (mode == 1) {
		file->buffer_length = file->buffer_size;
	}

	ioresult = (*file->read_fn)(file->handle, file->buffer, &file->buffer_length, file->idle_fn);

	if (ioresult == 2) {
		file->buffer_length = 0;
	}

	if (bytes_loaded != NULL) {
		*bytes_loaded = file->buffer_length;
	}

	if (ioresult != 0) {
		return ioresult;
	}

	file->position += file->buffer_length;

	if (!file->file_mode.binary_io) {
		int i;

		buffer_start = file->buffer;
		for (i = file->buffer_length; i != 0; i--) {
			unsigned char c = *buffer_start;
			buffer_start++;
			if (c == '\n') {
				file->position++;
			}
		}
	}

	return 0;
}

int __flush_buffer(FILE* file, size_t* bytes_flushed)
{
	size_t buffer_len;
	int ioresult;

	buffer_len = file->buffer_ptr - file->buffer;

	if (buffer_len) {
		file->buffer_length = buffer_len;

		if (!file->file_mode.binary_io)
			__convert_from_newlines(file->buffer, &file->buffer_length);

		ioresult = (*file->write_fn)(file->handle, file->buffer,
		                             &file->buffer_length, file->idle_fn);

		if (bytes_flushed)
			*bytes_flushed = file->buffer_length;

		if (ioresult)
			return ioresult;

		file->position += file->buffer_length;
	}

	__prep_buffer(file);

	return __no_io_error;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int setvbuf(FILE* file, char* buffer, int mode, size_t size)
{
	unsigned char* file_bytes = (unsigned char*)file;
	unsigned short mode_bits = *(unsigned short*)(file_bytes + 4);
	int io_mode = (mode_bits >> 6) & 7;

	if (mode == _IONBF) {
		fflush(file);
	}

	if (file->file_state.io_state != __neutral || io_mode == 0) {
		return -1;
	}

	if (mode != _IONBF && mode != _IOLBF && mode != _IOFBF) {
		return -1;
	}

	if (file->buffer != NULL && file->file_state.free_buffer != 0) {
		free(file->buffer);
	}

	__begin_critical_region(2);

	file->file_mode.buffer_mode = mode;
	file->file_state.free_buffer = 0;
	file->buffer = (unsigned char*)&file->char_buffer;
	file->buffer_ptr = (unsigned char*)&file->char_buffer;
	file->buffer_size = 1;
	file->buffer_length = 0;
	file->buffer_alignment = 0;

	if (mode == _IONBF || size < 1) {
		*file->buffer_ptr = 0;
		__end_critical_region(2);
		return 0;
	}

	if (buffer == NULL) {
		buffer = (char*)malloc(size);
		if (buffer == NULL) {
			__end_critical_region(2);
			return -1;
		}
		file->file_state.free_buffer = 1;
	}

	file->buffer = (unsigned char*)buffer;
	file->buffer_ptr = file->buffer;
	file->buffer_size = size;
	file->buffer_alignment = 0;

	__end_critical_region(2);
	return 0;
}
