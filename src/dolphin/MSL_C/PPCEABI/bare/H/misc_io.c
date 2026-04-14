#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/abort_exit.h"

void clearerr(FILE* stream) {
    stream->file_state.eof = 0;
    stream->file_state.error = 0;
}

void __stdio_atexit(void) {
    __stdio_exit = __close_all;
}
