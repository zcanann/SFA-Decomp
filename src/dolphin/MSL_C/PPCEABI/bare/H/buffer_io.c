#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"

static inline void prep_buffer(FILE* file)
{
    file->buffer_ptr = file->buffer;
    file->buffer_length = file->buffer_size;
    file->buffer_length -= file->position & file->buffer_alignment;
    file->buffer_position = file->position;
}

int __flush_buffer(FILE* file, size_t* bytes_flushed)
{
    size_t buffer_len;
    int ioresult;

    buffer_len = file->buffer_ptr - file->buffer;
    if (buffer_len != 0) {
        file->buffer_length = buffer_len;
        ioresult = file->write_fn(file->handle, file->buffer, &file->buffer_length, file->idle_fn);
        if (bytes_flushed != NULL) {
            *bytes_flushed = file->buffer_length;
        }
        if (ioresult != 0) {
            return ioresult;
        }
        file->position += file->buffer_length;
    }

    prep_buffer(file);
    return __no_io_error;
}

void __prep_buffer(FILE* file)
{
    prep_buffer(file);
}
