#include "PowerPC_EABI_Support/MetroTRK/trk.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/ansi_files.h"
#include "TRK_MINNOW_DOLPHIN/Os/dolphin/targsupp.h"

int __read_file(__file_handle file, unsigned char* buffer, size_t* count, __idle_proc idle_fn);
int __write_file(__file_handle file, unsigned char* buffer, size_t* count, __idle_proc idle_fn);

int __read_console(__file_handle file, unsigned char* buffer, size_t* count, __idle_proc idle_fn) {
    if (GetUseSerialIO() == 0) {
        return DS_IOError;
    }

    return __read_file(DS_Stdin, buffer, count, idle_fn);
}

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
    result = TRKAccessFile(DSMSG_WriteFile, DS_Stdout, &countTemp, buffer);
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

int __read_file(__file_handle file, unsigned char* buffer, size_t* count, __idle_proc idle_fn) {
    u32 countTemp;
    u32 result;

    if (GetTRKConnected() == DS_NoError) {
        return DS_IOError;
    }

    countTemp = *count;
    result = TRKAccessFile(DSMSG_ReadFile, file, &countTemp, buffer);
    *count = countTemp;

    switch ((u8)result) {
    case DS_IONoError:
        return DS_IONoError;
    case DS_IOEOF:
        return DS_IOEOF;
    }

    return DS_IOError;
}

int __write_file(__file_handle file, unsigned char* buffer, size_t* count, __idle_proc idle_fn) {
    u32 countTemp;
    u32 result;

    if (GetTRKConnected() == DS_NoError) {
        return DS_IOError;
    }

    countTemp = *count;
    result = TRKAccessFile(DSMSG_WriteFile, file, &countTemp, buffer);
    *count = countTemp;

    switch ((u8)result) {
    case DS_IONoError:
        return DS_IONoError;
    case DS_IOEOF:
        return DS_IOEOF;
    }

    return DS_IOError;
}

int __open_file(const char* name, file_modes mode, __file_handle* handle) {
    u32 result;
    u8 binaryIO;
    u8 ioMode;
    u8 openMode;
    u8 trkMode;

    if (GetTRKConnected() == DS_NoError) {
        return DS_IOError;
    }

    trkMode = 0;
    openMode = mode.open_mode;
    ioMode = mode.io_mode;
    binaryIO = mode.binary_io;

    switch (openMode) {
    case 0:
        trkMode |= 0x01;
        break;
    case 2:
        trkMode |= 0x02;
        break;
    case 1:
        trkMode |= 0x04;
        break;
    }

    switch (ioMode) {
    case 1:
        trkMode |= 0x01;
        break;
    case 2:
        trkMode |= 0x02;
        break;
    case 6:
        trkMode |= 0x04;
        break;
    case 3:
        trkMode |= 0x12;
        break;
    case 7:
        trkMode |= 0x07;
        break;
    }

    if (binaryIO == 1) {
        trkMode |= 0x08;
    }

    result = TRKOpenFile(DSMSG_OpenFile, (u32)name, trkMode, (u8*)handle);

    switch ((u8)result) {
    case DS_IONoError:
        return DS_IONoError;
    case DS_IOEOF:
        return DS_IOEOF;
    }

    return DS_IOError;
}

int __close_file(__file_handle file) {
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

int __position_file(__file_handle file, fpos_t* position, int mode, __idle_proc idle_proc) {
    u32 modeConverted;
    u32 result;

    modeConverted = 0;

    if (GetTRKConnected() == DS_NoError) {
        return DS_IOError;
    }

    if (mode == 0) {
        modeConverted = 0;
    } else if (mode == 1) {
        modeConverted = 1;
    } else if (mode == 2) {
        modeConverted = 2;
    }

    result = TRKPositionFile(DSMSG_PositionFile, file, position, (u8)modeConverted);

    switch ((u8)result) {
    case DS_IONoError:
        return DS_IONoError;
    case DS_IOEOF:
        return DS_IOEOF;
    }

    return DS_IOError;
}

