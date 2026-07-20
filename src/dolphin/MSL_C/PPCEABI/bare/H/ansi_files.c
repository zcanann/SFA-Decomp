#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/file_io.h"

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
     &__TRK_write_console,
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
     &__TRK_write_console,
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
     &__TRK_write_console,
     &__write_console,
     &__close_console,
     0,
     &__files[3]},
};

unsigned int __flush_all(void)
{
    unsigned int retval = 0;
    FILE* file = __files;

    while (file != NULL) {
        if (file->file_mode.file_kind && fflush(file)) {
            retval = -1;
        }
        file = file->next_file_struct;
    }

    return retval;
}

void __close_all(void)
{
    FILE* file = __files;
    FILE* prev;

    while (file != NULL) {
        if (file->file_mode.file_kind != __closed_file) {
            fclose(file);
        }

        prev = file;
        file = file->next_file_struct;
        if (prev->is_dynamically_allocated) {
            free(prev);
        } else {
            prev->file_mode.file_kind = __strinFile;
            if (file != NULL && file->is_dynamically_allocated) {
                prev->next_file_struct = NULL;
            }
        }
    }
}
