/* TODO: restore stripped imported address metadata if needed. */

#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msghndlr.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msgbuf.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/nubevent.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/MWTrace.h"
#include "PowerPC_EABI_Support/MetroTRK/trk.h"
#include <string.h>

typedef struct DSCPUType {
    u8 cpuMajor;
    u8 cpuMinor;
    u8 bigEndian;
    u8 defaultTypeSize;
    u8 fpTypeSize;
    u8 extended1TypeSize;
    u8 extended2TypeSize;
} DSCPUType;

DSError TRKTargetVersions(DSVersions* versions);
DSError TRKTargetSupportMask(u8 mask[32]);
DSError TRKTargetCPUType(DSCPUType* cpuType);

BOOL IsTRKConnected;

void OutputData(void* data, int length) {
    // u8 byte;
    int i;
    u8* datapointer = data;

    for (i = 0; i < length; i++) {
        MWTRACE(8, "%02x ", datapointer[i]);
        if (i % 16 == 15) {
            MWTRACE(8, "\n");
        }
    }

    MWTRACE(8, "\n");
}

BOOL GetTRKConnected(void) {
    return IsTRKConnected;
}

void SetTRKConnected(BOOL isTRKConnected) {
    IsTRKConnected = isTRKConnected;
}

DSError TRKSendACK(TRKBuffer* buffer) {
    DSError err;
    MWTRACE(1, "SendACK : Calling MessageSend\n");
    err = TRKMessageSend(buffer);
    MWTRACE(1, "MessageSend err : %ld\n", err);
    return err;
}

DSError TRKStandardACK(TRKBuffer* buffer, MessageCommandID commandID,
                              DSReplyError replyError) {
    int retries;
    DSError result;

    TRKResetBuffer(buffer, TRUE);
    TRKAppendBuffer1_ui8(buffer, commandID);
    TRKAppendBuffer1_ui8(buffer, replyError);

    retries = 3;
    do {
        result = TRKMessageSend(buffer);
        retries--;
        if (result == DS_NoError) {
            break;
        }
    } while (retries > 0);
    return result;
}

DSError TRKDoUnsupported(TRKBuffer* buffer) {
    return TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_UnsupportedCommandError);
}

DSError TRKDoConnect(TRKBuffer* buffer) {
    IsTRKConnected = TRUE;
    return TRKStandardACK(buffer, 0x80, DSREPLY_NoError);
}

DSError TRKDoDisconnect(TRKBuffer* buffer) {
    IsTRKConnected = FALSE;
    return TRKStandardACK(buffer, 0x80, DSREPLY_NoError);
}

DSError TRKDoReset(TRKBuffer* buffer) {
    TRKStandardACK(buffer, 0x80, DSREPLY_NoError);
    __TRK_reset();
    return DS_NoError;
}

DSError TRKDoOverride(TRKBuffer* buffer) {
    TRKStandardACK(buffer, 0x80, DSREPLY_NoError);
    __TRK_copy_vectors();
    return DS_NoError;
}

DSError TRKDoVersions(TRKBuffer* buffer) {
    DSError err;
    DSVersions versions;

    if (buffer->length != 1) {
        return TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
    }

    TRKResetBuffer(buffer, TRUE);
    TRKAppendBuffer1_ui8(buffer, DSMSG_ReplyACK);
    TRKAppendBuffer1_ui8(buffer, DSREPLY_NoError);
    err = TRKTargetVersions(&versions);
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, versions.kernelMajor);
    }
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, versions.kernelMinor);
    }
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, versions.protocolMajor);
    }
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, versions.protocolMinor);
    }
    if (err != DS_NoError) {
        return TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_CWDSError);
    }
    return TRKSendACK(buffer);
}

DSError TRKDoSupportMask(TRKBuffer* buffer) {
    DSError err;
    u8 mask[32];

    if (buffer->length != 1) {
        return TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
    }

    TRKResetBuffer(buffer, TRUE);
    TRKAppendBuffer1_ui8(buffer, DSMSG_ReplyACK);
    TRKAppendBuffer1_ui8(buffer, DSREPLY_NoError);
    err = TRKTargetSupportMask(mask);
    if (err == DS_NoError) {
        err = TRKAppendBuffer(buffer, mask, sizeof(mask));
    }
    if (err != DS_NoError) {
        return TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_CWDSError);
    }
    return TRKSendACK(buffer);
}

DSError TRKDoCPUType(TRKBuffer* buffer) {
    DSError err;
    DSCPUType cpuType;

    if (buffer->length != 1) {
        return TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
    }

    TRKResetBuffer(buffer, TRUE);
    TRKAppendBuffer1_ui8(buffer, DSMSG_ReplyACK);
    TRKAppendBuffer1_ui8(buffer, DSREPLY_NoError);
    err = TRKTargetCPUType(&cpuType);
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, cpuType.cpuMajor);
    }
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, cpuType.cpuMinor);
    }
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, cpuType.bigEndian);
    }
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, cpuType.defaultTypeSize);
    }
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, cpuType.fpTypeSize);
    }
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, cpuType.extended1TypeSize);
    }
    if (err == DS_NoError) {
        err = TRKAppendBuffer1_ui8(buffer, cpuType.extended2TypeSize);
    }
    if (err != DS_NoError) {
        return TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_CWDSError);
    }
    return TRKSendACK(buffer);
}

DSError TRKDoReadMemory(TRKBuffer* buffer) {
    u8 buf[0x820] __attribute__((aligned(32)));
    size_t tempLength;
    int result;
    int replyErr;
    int options;
    size_t length;
    u32 start;

    start = *(u32*)(buffer->data + 16);
    length = *(u16*)(buffer->data + 12);
    options = buffer->data[8];

    MWTRACE(1, "ReadMemory (0x%02x) : 0x%08x 0x%08x 0x%08x\n", buffer->data[4], start, length,
            options);

    if (options & DSMSGMEMORY_Extended) {
        return TRKStandardACK(buffer, DSMSG_ReplyACK, DSREPLY_UnsupportedOptionError);
    }

    tempLength = length;

    if (options & DSMSGMEMORY_Space_data) {
        result = TRKTargetAccessARAM(buf, start, &tempLength, TRUE);
    } else {
        result = TRKTargetAccessMemory(buf, start, &tempLength,
                                       options & DSMSGMEMORY_Userview ? 0 : 1, TRUE);
    }

    TRKResetBuffer(buffer, 0);

    if (result == DS_NoError) {
        CommandReply reply;
        memset(&reply, 0, sizeof(CommandReply));
        reply.replyError.b = result;
        reply._00 = tempLength + 0x40;
        reply.commandID.b = DSMSG_ReplyACK;
        TRKAppendBuffer(buffer, &reply, sizeof(CommandReply));

        if (options & 0x40) {
            result = TRKAppendBuffer(buffer, buf + (start & 0x1F), tempLength);
        } else {
            result = TRKAppendBuffer(buffer, buf, tempLength);
        }
    }

    if (result) {
        switch (result) {
        case DS_CWDSException:
            replyErr = DSREPLY_CWDSException;
            break;
        case DS_InvalidMemory:
            replyErr = DSREPLY_InvalidMemoryRange;
            break;
        case DS_InvalidProcessID:
            replyErr = DSREPLY_InvalidProcessID;
            break;
        case DS_InvalidThreadID:
            replyErr = DSREPLY_InvalidThreadID;
            break;
        case DS_OSError:
            replyErr = DSREPLY_OSError;
            break;
        default:
            replyErr = DSREPLY_CWDSError;
            break;
        }
        return TRKStandardACK(buffer, DSMSG_ReplyACK, replyErr);
    }

    return TRKSendACK(buffer);
}

DSError TRKDoWriteMemory(TRKBuffer* b) {
    u8 buf[0x820] __attribute__((aligned(32)));
    size_t tempLength;
    int options;
    int result;
    int replyErr;
    size_t length;
    u32 start;

    start = *(u32*)(&b->data[16]);
    length = *(u16*)(&b->data[12]);
    options = b->data[8];

    MWTRACE(1, "WriteMemory (0x%02x) : 0x%08x 0x%08x 0x%08x\n", (unsigned int)b->data[0x4], start,
            length, options);

    if (options & DSMSGMEMORY_Extended) {
        return TRKStandardACK(b, DSMSG_ReplyACK, DSMSG_ReadRegisters);
    }

    tempLength = length;

    TRKSetBufferPosition(b, DSMSGMEMORY_Space_data);
    if (options & DSMSGMEMORY_Space_data) {
        TRKReadBuffer(b, buf + (start & 0x1f), tempLength);
        result = TRKTargetAccessARAM(buf, start, &tempLength, FALSE);
    } else {
        TRKReadBuffer(b, buf, tempLength);
        result = TRKTargetAccessMemory(buf, start, &tempLength,
                                       options & DSMSGMEMORY_Userview ? 0 : 1, FALSE);
    }

    TRKResetBuffer(b, 0);

    if (result == DS_NoError) {
        CommandReply reply;
        memset(&reply, 0, sizeof(CommandReply));
        reply._00 = 0x40;
        reply.commandID.b = DSMSG_ReplyACK;
        reply.replyError.b = result;
        result = TRKAppendBuffer(b, &reply, sizeof(CommandReply));
    }

    if (result != DS_NoError) {
        switch (result) {
        case DS_CWDSException:
            replyErr = DSREPLY_CWDSException;
            break;
        case DS_InvalidMemory:
            replyErr = DSREPLY_InvalidMemoryRange;
            break;
        case DS_InvalidProcessID:
            replyErr = DSREPLY_InvalidProcessID;
            break;
        case DS_InvalidThreadID:
            replyErr = DSREPLY_InvalidThreadID;
            break;
        case DS_OSError:
            replyErr = DSREPLY_OSError;
            break;
        default:
            replyErr = DSREPLY_CWDSError;
            break;
        }
        return TRKStandardACK(b, DSMSG_ReplyACK, replyErr);
    }

    return TRKSendACK(b);
}

DSError TRKDoReadRegisters(TRKBuffer* b) {
    int error;
    u8 options;
    u16 firstRegister;
    u16 lastRegister;
    size_t registersLength;
    CommandReply local_50;

    options = b->data[8];
    firstRegister = *(u16*)(b->data + 12);
    lastRegister = *(u16*)(b->data + 16);

    if (firstRegister > lastRegister) {
        return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_InvalidRegisterRange);
    }

    local_50.commandID.b = DSMSG_ReplyACK;
    local_50._00 = 0x468;

    TRKResetBuffer(b, 0);
    MWTRACE(4, "DoReadRegisters : Buffer length 0x%08x\n", b->length);

    TRKAppendBuffer_ui8(b, (u8*)&local_50, sizeof(CommandReply));
    MWTRACE(4, "DoReadRegisters : Buffer length 0x%08x\n", b->length);

    error = TRKTargetAccessDefault(0, 36, b, &registersLength, TRUE);
    MWTRACE(4, "DoReadRegisters : Error reading  default regs 0x%08x\n", error);
    MWTRACE(4, "DoReadRegisters : Buffer length 0x%08x\n", b->length);

    if (error == DS_NoError) {
        error = TRKTargetAccessFP(0, 33, b, &registersLength, TRUE);
    }
    MWTRACE(4, "DoReadRegisters : Error FP regs 0x%08x\n", error);
    MWTRACE(4, "DoReadRegisters : Buffer length 0x%08x\n", b->length);
    if (error == DS_NoError) {
        error = TRKTargetAccessExtended1(0, 0x60, b, &registersLength, TRUE);
    }
    MWTRACE(4, "DoReadRegisters : Error extended1 regs 0x%08x\n", error);
    MWTRACE(4, "DoReadRegisters : Buffer length 0x%08x\n", b->length);
    if (error == DS_NoError) {
        error = TRKTargetAccessExtended2(0, 31, b, &registersLength, TRUE);
    }
    MWTRACE(4, "DoReadRegisters : Error extended2 regs 0x%08x\n", error);
    MWTRACE(4, "DoReadRegisters : Buffer length 0x%08x\n", b->length);

    // Check if there was an error, and respond accordingly
    if (error != DS_NoError) {
        int replyError;
        switch (error) {
        case DS_UnsupportedError:
            replyError = DSREPLY_UnsupportedOptionError;
            break;
        case DS_InvalidRegister:
            replyError = DSREPLY_InvalidRegisterRange;
            break;
        case DS_CWDSException:
            replyError = DSREPLY_CWDSException;
            break;
        case DS_InvalidProcessID:
            replyError = DSREPLY_InvalidProcessID;
            break;
        case DS_InvalidThreadID:
            replyError = DSREPLY_InvalidThreadID;
            break;
        case DS_OSError:
            replyError = DSREPLY_OSError;
            break;
        default:
            replyError = DSREPLY_CWDSError;
        }

        return TRKStandardACK(b, DSMSG_ReplyACK, replyError);
    } else {
        // No error, send ack
        return TRKSendACK(b);
    }
}

DSError TRKDoWriteRegisters(TRKBuffer* b) {
    int error;
    int replyError;
    u8 options;
    u16 firstRegister;
    u16 lastRegister;
    size_t registersLength;

    options = b->data[8];
    firstRegister = *(u16*)(b->data + 12);
    lastRegister = *(u16*)(b->data + 16);

    TRKSetBufferPosition(b, 0);

    if (firstRegister > lastRegister) {
        return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_InvalidRegisterRange);
    }

    TRKSetBufferPosition(b, 0x40);

    switch (options) {
    case DSREG_Default:
        error = TRKTargetAccessDefault(firstRegister, lastRegister, b, &registersLength, FALSE);
        break;
    case DSREG_FP:
        error = TRKTargetAccessFP(firstRegister, lastRegister, b, &registersLength, FALSE);
        break;
    case DSREG_Extended1:
        error = TRKTargetAccessExtended1(firstRegister, lastRegister, b, &registersLength, FALSE);
        break;
    case DSREG_Extended2:
        error = TRKTargetAccessExtended2(firstRegister, lastRegister, b, &registersLength, FALSE);
        break;
    default:
        // invalid option
        error = DS_UnsupportedError;
        break;
    }

    TRKResetBuffer(b, 0);

    if (error == DS_NoError) {
        CommandReply local_50;
        memset(&local_50, 0, sizeof(CommandReply));
        local_50._00 = 0x40;
        local_50.commandID.b = DSMSG_ReplyACK;
        local_50.replyError.b = error;
        error = TRKAppendBuffer(b, (u8*)&local_50, sizeof(CommandReply));
    }

    // Check if there was an error, and respond accordingly
    if (error != DS_NoError) {
        switch (error) {
        case DS_UnsupportedError:
            replyError = DSREPLY_UnsupportedOptionError;
            break;
        case DS_InvalidRegister:
            replyError = DSREPLY_InvalidRegisterRange;
            break;
        case DS_MessageBufferReadError:
            replyError = DSREPLY_PacketSizeError;
            break;
        case DS_CWDSException:
            replyError = DSREPLY_CWDSException;
            break;
        case DS_InvalidProcessID:
            replyError = DSREPLY_InvalidProcessID;
            break;
        case DS_InvalidThreadID:
            replyError = DSREPLY_InvalidThreadID;
            break;
        case DS_OSError:
            replyError = DSREPLY_OSError;
            break;
        default:
            replyError = DSREPLY_CWDSError;
        }

        return TRKStandardACK(b, DSMSG_ReplyACK, replyError);
    } else {
        // No error, send ack
        return TRKSendACK(b);
    }
}

DSError TRKDoFlushCache(TRKBuffer* b) {
    DSError err;
    u8 command;
    u8 options;
    u32 rangeStart;
    u32 rangeEnd;

    if (b->length != 0xA) {
        return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_PacketSizeError);
    }

    TRKSetBufferPosition(b, 0);

    err = TRKReadBuffer1_ui8(b, &command);
    if (err == DS_NoError) {
        err = TRKReadBuffer1_ui8(b, &options);
    }
    if (err == DS_NoError) {
        err = TRKReadBuffer1_ui32(b, &rangeStart);
    }
    if (err == DS_NoError) {
        err = TRKReadBuffer1_ui32(b, &rangeEnd);
    }

    if (err == DS_NoError && rangeStart > rangeEnd) {
        return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_InvalidMemoryRange);
    }

    if (err == DS_NoError) {
        err = TRKTargetFlushCache(options, (void*)rangeStart, (void*)rangeEnd);
    }

    if (err != DS_NoError) {
        if (err == DS_UnsupportedError) {
            return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_UnsupportedOptionError);
        }
        return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_CWDSError);
    }

    return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_NoError);
}

DSError TRKDoContinue(TRKBuffer*) {
    MWTRACE(1, "DoContinue\n");
    if (!TRKTargetStopped()) {
        u8 arr[0x40];
        memset(arr, 0, 0x40);

        arr[4] = 0x80;
        *(u32*)arr = 0x40;
        arr[8] = 0x16;

        TRKWriteUARTN(arr, 0x40);
        return DS_NoError;
    } else {
        u8 arr[0x40];
        memset(arr, 0, 0x40);

        arr[4] = 0x80;
        *(u32*)arr = 0x40;
        arr[8] = 0x00;

        TRKWriteUARTN(arr, 0x40);
        return TRKTargetContinue();
    }
}

DSError TRKDoStep(TRKBuffer* b) {
    DSError result;
    u8 options;
    u8 count;
    u32 rangeStart;
    u32 rangeEnd;
    u32 pc;
    TRKSetBufferPosition(b, 0);

    options = *(u8*)&b->data[8];
    rangeStart = *(u32*)&b->data[16];
    rangeEnd = *(u32*)&b->data[20];

    switch (options) {
    case DSSTEP_IntoCount:
    case DSSTEP_OverCount:
        count = b->data[12];
        if (count >= 1) {
            break;
        }
        return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_ParameterError);
    case DSSTEP_IntoRange:
    case DSSTEP_OverRange:
        pc = TRKTargetGetPC();
        if (pc >= rangeStart && pc <= rangeEnd) {
            break;
        }
        return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_ParameterError);
    default:
        return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_UnsupportedOptionError);
    }

    if (!TRKTargetStopped()) {
        return TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_NotStopped);
    } else {
        result = TRKStandardACK(b, DSMSG_ReplyACK, DSREPLY_NoError);
        switch (options) {
        case DSSTEP_IntoCount:
        case DSSTEP_OverCount:
            result = TRKTargetSingleStep(count, (options == DSSTEP_OverCount));
            break;
        case DSSTEP_IntoRange:
        case DSSTEP_OverRange:
            result = TRKTargetStepOutOfRange(rangeStart, rangeEnd, (options == DSSTEP_OverRange));
            break;
        }

        return result;
    }
}

DSError TRKDoStop(TRKBuffer* b) {
    MessageCommandID c;

    switch (TRKTargetStop()) {
    case DS_NoError:
        c = DSMSG_Ping;
        break;
    case DS_InvalidProcessID:
        c = '!';
        break;
    case DS_InvalidThreadID:
        c = '\"';
        break;
    case DS_OSError:
        c = ' ';
        break;
    default:
        c = DSMSG_Connect;
        break;
    }

    return TRKStandardACK(b, DSMSG_ReplyACK, c);
}

DSError TRKDoSetOption(TRKBuffer* message) {
    u8 enable = message->data[0xc];

    if (message->data[0x8] == '\1') {
        usr_puts_serial("\nMetroTRK Option : SerialIO - ");
        if (enable) {
            usr_puts_serial("Enable\n");
        } else {
            usr_puts_serial("Disable\n");
        }
        SetUseSerialIO(enable);
    }

    TRKStandardACK(message, DSMSG_ReplyACK, DS_NoError);

    return 0;
}
