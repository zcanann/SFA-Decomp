#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"

extern unsigned char lbl_803DADF0[];
extern unsigned char lbl_803DACF0[];
extern unsigned char lbl_803DABF0[];

int __TRK_write_console(__file_handle file, unsigned char* buff, size_t* count, __idle_proc idle_fn);

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
     lbl_803DADF0,
     256,
     lbl_803DADF0,
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
     lbl_803DACF0,
     256,
     lbl_803DACF0,
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
     lbl_803DABF0,
     256,
     lbl_803DABF0,
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

int fclose(FILE*);
int fflush(FILE*);

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
