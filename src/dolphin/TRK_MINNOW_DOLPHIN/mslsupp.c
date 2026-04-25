#include "PowerPC_EABI_Support/MetroTRK/trk.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"
#include "TRK_MINNOW_DOLPHIN/Os/dolphin/targsupp.h"

int __TRK_write_console(__file_handle file, unsigned char* buffer, size_t* count, __idle_proc idle_fn) {
    u32 countTemp;
    u32 result;

    if (GetUseSerialIO() == 0) {
        return DS_IOError;
    }

    if (GetTRKConnected() == DS_NoError) {
        return DS_IOError;
    }

    countTemp = *count;
    result = TRKAccessFile(0xD1, 0, &countTemp, buffer);
    *count = countTemp;

    switch ((u8)result) {
    case DS_IONoError:
        return DS_IONoError;
    case DS_IOEOF:
        return DS_IOEOF;
    }

    return DS_IOError;
}

int __close_console(__file_handle file) {
    u32 result;

    if (GetTRKConnected() == DS_NoError) {
        return DS_IOError;
    }

    result = TRKCloseFile(DSMSG_CloseFile, file);

    switch ((u8)result) {
    case DS_IONoError:
        return DS_IONoError;
    case DS_IOEOF:
        return DS_IOEOF;
    }

    return DS_IOError;
}
