#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"

extern FILE __files[4];
int fclose(FILE*);
int fflush(FILE*);
void fn_8028D574(void* p);

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
            fn_8028D574(prev);
        } else {
            prev->file_mode.file_kind = __strinFile;
            if (file != NULL && file->is_dynamically_allocated) {
                prev->next_file_struct = NULL;
            }
        }
    }
}
