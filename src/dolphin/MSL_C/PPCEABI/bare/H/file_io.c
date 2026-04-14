#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/file_io.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/alloc.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/buffer_io.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/critical_regions.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/FILE_POS.h"

inline FILE* freopen(const char* name, const char* mode, FILE* file)
{
    file_modes modes;

    __stdio_atexit();

    if (!file) {
        return NULL;
    }

    fclose(file);
    clearerr(file);

    if (!__get_file_modes(mode, &modes)) {
        return NULL;
    }

    __init_file(file, modes, 0, 0x400);

    if (__open_file(name, modes, &file->handle)) {
        file->file_mode.file_kind = __closed_file;
        if (file->file_state.free_buffer) {
            free(file->buffer);
        }
        return NULL;
    }
    if (modes.io_mode & __append) {
        fseek(file, 0, SEEK_END);
    }

    return file;
}

int fclose(FILE* file) {
    int flush_result, close_result;

    if (file == NULL) {
        return -1;
    }
    if (file->file_mode.file_kind == __closed_file) {
        return 0;
    }
    flush_result = fflush(file);
    close_result = file->close_fn(file->handle);
    file->file_mode.file_kind = __closed_file;
    file->handle = NULL;
    if (file->file_state.free_buffer) {
        free(file->buffer);
    }
    return (flush_result || close_result) ? -1 : 0;
}

int fflush(FILE* file) {
    unsigned long pos;

    if (file == NULL) {
        return __flush_all();
    }
    if (file->file_state.error != 0 || file->file_mode.file_kind == __closed_file) {
        return -1;
    }
    if (file->file_mode.io_mode == __read) {
        return 0;
    }
    if (file->file_state.io_state >= __rereading) {
        file->file_state.io_state = __reading;
    }
    if (file->file_state.io_state == __reading) {
        file->buffer_length = 0;
    }
    if (file->file_state.io_state != __writing) {
        file->file_state.io_state = __neutral;
        return 0;
    }
    if (file->file_mode.file_kind != __disk_file) {
        pos = 0;
    } else {
        pos = ftell(file);
    }
    if (__flush_buffer(file, 0) != __no_io_error) {
        file->file_state.error = 1;
        file->buffer_length = 0;
        return -1;
    }
    file->file_state.io_state = __neutral;
    file->position = pos;
    file->buffer_length = 0;
    return 0;
}

FILE* fopen(const char* name, const char* mode)
{
    FILE* file;

    __begin_critical_region(stdin_access);

    file = freopen(name, mode, (FILE*)__find_unopened_file());

    __end_critical_region(stdin_access);

    return file;
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
int __get_file_modes(const char* mode, file_modes* modes)
{
	const char* mode_ptr;
	signed char mode_char;
	int mode_str;
	unsigned char open_mode;
	int io_mode;

	modes->file_kind = __disk_file;
	mode_char = mode[0];
	mode_str = mode_char;
#ifndef __NO_WIDE_CHAR
	modes->file_orientation = UNORIENTED;
#endif
	modes->binary_io = 0;

	switch (mode_str)
	{
		case 'r':
			open_mode = __must_exist;
			break;
		
		case 'w':
			open_mode = __create_or_truncate;
			break;

		case 'a':
			open_mode = __create_if_necessary;
			break;
		
		default:
			return(0);
	}

	modes->open_mode = open_mode;
	mode_ptr = mode + 1;

	switch (*mode_ptr++)
	{
		case 'b':
			modes->binary_io = 1;
			
			if (*mode_ptr == '+')
				mode_str = (mode_str << 8) | '+';
			
			break;
			
		case '+':
			mode_str = (mode_str << 8) | '+';
			
			if (*mode_ptr == 'b')
				modes->binary_io = 1;
			
			break;
	}
	
	switch (mode_str)
	{
		case 'r':
			io_mode = __read;
			break;
						
		case 'w':
			io_mode = __write;
			break;
			
		case 'a':
			io_mode = __write | __append;
			break;
			
		case 'r+':
			io_mode = __read_write;
			break;
			
		case 'w+':
			io_mode = __read_write;
			break;
			
		case 'a+':
			io_mode = __read_write | __append;
			break;
	}
	
	modes->io_mode = io_mode;
	
	return(1);
}
