#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/alloc.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/file_io.h"
#include <string.h>

extern int __position_file(__file_handle file, fpos_t* position, int mode,
                           __idle_proc idle_proc);
extern int __read_file(__file_handle file, unsigned char* buff, size_t* count,
                       __idle_proc idle_proc);
extern int __write_file(__file_handle file, unsigned char* buff, size_t* count,
                        __idle_proc idle_proc);
extern int __close_file(__file_handle file);

static unsigned char stdin_buff[0x100];
static unsigned char stdout_buff[0x100];
static unsigned char stderr_buff[0x100];

FILE __files[4] = {
    {0,
     {0, 1, 1, 2, 0},
     {0, 0, 0, 0},
     0,
     0,
     0,
     {0, 0},
     {0, 0},
     0,
     stdin_buff,
     sizeof(stdin_buff),
     stdin_buff,
     0,
     0,
     0,
     0,
     NULL,
     &__read_console,
     &__write_console,
     &__close_console,
     0,
     &__files[1]},
    {1,
     {0, 2, 1, 2, 0},
     {0, 0, 0, 0},
     0,
     0,
     0,
     {0, 0},
     {0, 0},
     0,
     stdout_buff,
     sizeof(stdout_buff),
     stdout_buff,
     0,
     0,
     0,
     0,
     NULL,
     &__read_console,
     &__write_console,
     &__close_console,
     0,
     &__files[2]},
    {2,
     {0, 2, 0, 2, 0},
     {0, 0, 0, 0},
     0,
     0,
     0,
     {0, 0},
     {0, 0},
     0,
     stderr_buff,
     sizeof(stderr_buff),
     stderr_buff,
     0,
     0,
     0,
     0,
     NULL,
     &__read_console,
     &__write_console,
     &__close_console,
     0,
     &__files[3]},
};

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
FILE* __find_unopened_file(void) {
    FILE* result;
    FILE* prev;
    FILE* file = __files[2].next_file_struct;

    while (file != NULL) {
        if (file->file_mode.file_kind == __closed_file) {
            return file;
        }
        prev = file;
        file = file->next_file_struct;
    }

    result = (FILE*)malloc(sizeof(FILE));
    if (result == NULL) {
        result = NULL;
    } else {
        memset(result, 0, sizeof(FILE));
        result->is_dynamically_allocated = 1;
        prev->next_file_struct = result;
        return result;
    }

    return result;
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
void __init_file(FILE* file, file_modes mode, unsigned char* buffer, unsigned long buffer_size) {
    file->handle = 0;
    file->file_mode = mode;

    file->file_state.io_state = __neutral;
    file->file_state.free_buffer = 0;
    file->file_state.eof = 0;
    file->file_state.error = 0;

    file->position = 0;

    if (buffer_size != 0) {
        setvbuf(file, (char*)buffer, _IOFBF, buffer_size);
    } else {
        setvbuf(file, NULL, _IONBF, 0);
    }

    file->buffer_ptr = file->buffer;
    file->buffer_length = 0;

    if (file->file_mode.file_kind == __disk_file) {
        file->position_fn = __position_file;
        file->read_fn = __read_file;
        file->write_fn = __write_file;
        file->close_fn = __close_file;
    }

    file->idle_fn = NULL;
}

void __close_all() {
    FILE* file = &__files[0];
    FILE* last_file;

    __begin_critical_region(2);

    while (file != NULL) {
        if (file->file_mode.file_kind != __closed_file) {
            fclose(file);
        }

        last_file = file;
        file = file->next_file_struct;

        if (last_file->is_dynamically_allocated) {
            free(last_file);
        } else {
            last_file->file_mode.file_kind = __strinFile;
            if (file != NULL && file->is_dynamically_allocated) {
                last_file->next_file_struct = NULL;
            }
        }
    }

    __end_critical_region(2);
}

unsigned int __flush_all() {
  unsigned int retval = 0;
  FILE* __stream;

    __stream = &__files[0];
    while (__stream) {
        if ((__stream->file_mode.file_kind) && (fflush(__stream))) {
            retval = -1;
        }
        __stream = __stream->next_file_struct;
    };

    return retval;
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
int __flush_line_buffered_output_files(void) {
    int result = 0;
    FILE* file = &__files[0];
    unsigned char* file_bytes;
    unsigned short mode_bits;

    while (file != NULL) {
        file_bytes = (unsigned char*)file;
        mode_bits = *(unsigned short*)(file_bytes + 4);
        if ((((mode_bits >> 6) & 7) != 0) && (((file_bytes[4] >> 1) & 1) != 0) &&
            (((file_bytes[8] & 0xE0) >> 5) == 1u)) {
            if (fflush(file) != 0) {
                result = -1;
            }
        }

        file = file->next_file_struct;
    }

    return result;
}
