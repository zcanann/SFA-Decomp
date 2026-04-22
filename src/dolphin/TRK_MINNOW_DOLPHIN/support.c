/* TODO: restore stripped imported address metadata if needed. */

#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/support.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msg.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msgbuf.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msghndlr.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/serpoll.h"
#include <string.h>

asm DSError TRKSuppAccessFile(u32 file_handle, u8* data, size_t* count, u8* io_result,
                              BOOL need_reply, BOOL read) {
    nofralloc
    stwu r1, -0x50(r1)
    mflr r0
    stw r0, 0x54(r1)
    stmw r21, 0x24(r1)
    mr. r27, r4
    mr r23, r3
    mr r24, r5
    mr r26, r6
    mr r22, r7
    mr r29, r8
    beq _saf_0
    lwz r0, 0x0(r24)
    cmplwi r0, 0x0
    bne _saf_1
_saf_0:
    li r3, 0x2
    b _saf_24
_saf_1:
    li r0, 0x0
    li r25, 0x0
    stb r0, 0x0(r26)
    li r30, 0x0
    li r21, 0x0
    b _saf_22
_saf_2:
    subf r3, r30, r3
    li r0, 0x800
    cmplwi r3, 0x800
    bgt _saf_3
    mr r0, r3
_saf_3:
    mr r31, r0
    addi r3, r1, 0x10
    addi r4, r1, 0xc
    bl TRKGetFreeBuffer
    mr. r21, r3
    bne _saf_7
    cmpwi r29, 0x0
    li r5, 0xd0
    beq _saf_4
    li r5, 0xd1
_saf_4:
    lwz r6, 0xc(r1)
    lwz r4, 0xc(r6)
    cmplwi r4, 0x880
    blt _saf_5
    li r4, 0x301
    b _saf_6
_saf_5:
    addi r3, r4, 0x1
    addi r0, r4, 0x10
    stw r3, 0xc(r6)
    li r4, 0x0
    stbx r5, r6, r0
    lwz r3, 0x8(r6)
    addi r0, r3, 0x1
    stw r0, 0x8(r6)
_saf_6:
    mr r21, r4
_saf_7:
    cmpwi r21, 0x0
    bne _saf_8
    lwz r3, 0xc(r1)
    mr r4, r23
    bl TRKAppendBuffer1_ui32
    mr r21, r3
_saf_8:
    cmpwi r21, 0x0
    bne _saf_9
    lwz r3, 0xc(r1)
    clrlwi r4, r31, 16
    bl TRKAppendBuffer1_ui16
    mr r21, r3
_saf_9:
    cmpwi r29, 0x0
    bne _saf_10
    cmpwi r21, 0x0
    bne _saf_10
    lwz r3, 0xc(r1)
    mr r5, r31
    add r4, r27, r30
    bl TRKAppendBuffer_ui8
    mr r21, r3
_saf_10:
    cmpwi r21, 0x0
    bne _saf_21
    cmpwi r22, 0x0
    beq _saf_20
    li r0, 0x0
    cmpwi r29, 0x0
    sth r0, 0xa(r1)
    stb r0, 0x8(r1)
    beq _saf_11
    cmplwi r23, 0x0
    bne _saf_11
    li r0, 0x1
_saf_11:
    cmpwi r29, 0x0
    lwz r3, 0xc(r1)
    addi r4, r1, 0x14
    li r5, 0x5
    cntlzw r0, r0
    li r6, 0x3
    srwi r7, r0, 5
    bl TRKRequestSend
    mr. r21, r3
    bne _saf_12
    lwz r3, 0x14(r1)
    bl TRKGetBuffer
    li r4, 0x2
    mr r28, r3
    bl TRKSetBufferPosition
_saf_12:
    cmpwi r21, 0x0
    bne _saf_13
    mr r3, r28
    addi r4, r1, 0x8
    bl TRKReadBuffer1_ui8
    mr r21, r3
_saf_13:
    cmpwi r21, 0x0
    bne _saf_14
    mr r3, r28
    addi r4, r1, 0xa
    bl TRKReadBuffer1_ui16
    mr r21, r3
_saf_14:
    cmpwi r29, 0x0
    beq _saf_16
    cmpwi r21, 0x0
    bne _saf_16
    lhz r3, 0xa(r1)
    lwz r4, 0x8(r28)
    addi r0, r3, 0x5
    cmplw r4, r0
    beq _saf_15
    lbz r0, 0x8(r1)
    subi r3, r4, 0x5
    sth r3, 0xa(r1)
    cmplwi r0, 0x0
    bne _saf_15
    li r0, 0x1
    stb r0, 0x8(r1)
_saf_15:
    lhz r5, 0xa(r1)
    cmplw r5, r31
    bgt _saf_16
    mr r3, r28
    add r4, r27, r30
    bl TRKReadBuffer_ui8
    mr r21, r3
_saf_16:
    lhz r3, 0xa(r1)
    cmplw r3, r31
    beq _saf_19
    cmpwi r29, 0x0
    beq _saf_17
    cmplw r3, r31
    blt _saf_18
_saf_17:
    lbz r0, 0x8(r1)
    cmplwi r0, 0x0
    bne _saf_18
    li r0, 0x1
    stb r0, 0x8(r1)
_saf_18:
    mr r31, r3
    li r25, 0x1
_saf_19:
    lbz r0, 0x8(r1)
    stb r0, 0x0(r26)
    lwz r3, 0x14(r1)
    bl TRKReleaseBuffer
    b _saf_21
_saf_20:
    lwz r3, 0xc(r1)
    bl TRKMessageSend
    mr r21, r3
_saf_21:
    lwz r3, 0x10(r1)
    bl TRKReleaseBuffer
    add r30, r30, r31
_saf_22:
    cmpwi r25, 0x0
    bne _saf_23
    lwz r3, 0x0(r24)
    cmplw r30, r3
    bge _saf_23
    cmpwi r21, 0x0
    bne _saf_23
    lbz r0, 0x0(r26)
    cmplwi r0, 0x0
    beq _saf_2
_saf_23:
    stw r30, 0x0(r24)
    mr r3, r21
_saf_24:
    lmw r21, 0x24(r1)
    lwz r0, 0x54(r1)
    mtlr r0
    addi r1, r1, 0x50
    blr
}

DSError TRKRequestSend(TRKBuffer* msgBuf, int* bufferId, u32 p1, u32 p2, int p3) {
    int error = DS_NoError;
    TRKBuffer* buffer;
    u32 timer;
    int tries;
    u8 msg_command;
    u8 msg_error;
    BOOL badReply = TRUE;

    *bufferId = -1;

    for (tries = p2 + 1; tries != 0 && *bufferId == -1 && error == DS_NoError;
         tries--) {
        error = TRKMessageSend((TRK_Msg*)msgBuf);
        if (error == DS_NoError) {
            if (p3) {
                timer = 0;
            }

            while (TRUE) {
                do {
                    *bufferId = TRKTestForPacket();
                    if (*bufferId != -1) {
                        break;
                    }
                } while (!p3 || ++timer < 79999980);

                if (*bufferId == -1) {
                    break;
                }

                badReply = FALSE;

                buffer = TRKGetBuffer(*bufferId);
                TRKSetBufferPosition(buffer, 0);

                if ((error = TRKReadBuffer1_ui8(buffer, &msg_command))
                    != DS_NoError) {
                    break;
                }

                if (msg_command >= DSMSG_ReplyACK) {
                    break;
                }

                TRKProcessInput(*bufferId);
                *bufferId = -1;
            }

            if (*bufferId != -1) {
                if (buffer->length < p1) {
                    badReply = TRUE;
                }
                if (error == DS_NoError && !badReply) {
                    error = TRKReadBuffer1_ui8(buffer, &msg_error);
                }
                if (error == DS_NoError && !badReply) {
                    if (msg_command != DSMSG_ReplyACK
                        || msg_error != DSREPLY_NoError) {
                        badReply = TRUE;
                    }
                }
                if (error != DS_NoError || badReply) {
                    TRKReleaseBuffer(*bufferId);
                    *bufferId = -1;
                }
            }
        }
    }

    if (*bufferId == -1) {
        error = DS_Error800;
    }

    return error;
}

DSError HandleOpenFileSupportRequest(const char* path, u8 replyError, u32* param_3,
                                     u8* ioResult) {
    DSError error;
    int replyBufferId;
    int bufferId;
    TRKBuffer* replyBuffer;
    TRKBuffer* buffer;

    *param_3 = 0;
    error = TRKGetFreeBuffer(&bufferId, &buffer);

    if (error == DS_NoError) {
        error = TRKAppendBuffer1_ui8(buffer, DSMSG_OpenFile);
    }

    if (error == DS_NoError) {
        error = TRKAppendBuffer1_ui8(buffer, replyError);
    }

    if (error == DS_NoError) {
        error = TRKAppendBuffer1_ui16(buffer, strlen(path) + 1);
    }

    if (error == DS_NoError) {
        error = TRKAppendBuffer_ui8(buffer, (u8*)path, strlen(path) + 1);
    }

    if (error == DS_NoError) {
        *ioResult = DS_IONoError;
        error = TRKRequestSend(buffer, &replyBufferId, 7, 3, 0);

        if (error == DS_NoError) {
            replyBuffer = TRKGetBuffer(replyBufferId);
            TRKSetBufferPosition(replyBuffer, 2);
        }

        if (error == DS_NoError) {
            error = TRKReadBuffer1_ui8(replyBuffer, ioResult);
        }

        if (error == DS_NoError) {
            error = TRKReadBuffer1_ui32(replyBuffer, param_3);
        }

        TRKReleaseBuffer(replyBufferId);
    }

    TRKReleaseBuffer(bufferId);
    return error;
}

DSError HandleCloseFileSupportRequest(int replyError, u8* ioResult) {
    DSError error;
    int replyBufferId;
    int bufferId;
    TRKBuffer* buffer;
    TRKBuffer* replyBuffer;

    error = TRKGetFreeBuffer(&bufferId, &buffer);

    if (error == DS_NoError) {
        error = TRKAppendBuffer1_ui8(buffer, DSMSG_CloseFile);
    }

    if (error == DS_NoError) {
        error = TRKAppendBuffer1_ui32(buffer, replyError);
    }

    if (error == DS_NoError) {
        *ioResult = DS_IONoError;
        error = TRKRequestSend(buffer, &replyBufferId, 3, 3, 0);

        if (error == DS_NoError) {
            replyBuffer = TRKGetBuffer(replyBufferId);
            TRKSetBufferPosition(replyBuffer, 2);
        }

        if (error == DS_NoError) {
            error = TRKReadBuffer1_ui8(replyBuffer, ioResult);
        }

        TRKReleaseBuffer(replyBufferId);
    }

    TRKReleaseBuffer(bufferId);
    return error;
}

DSError HandlePositionFileSupportRequest(u32 replyErr, u32 param_2, u8 param_3,
                                         u8* ioResult) {
    DSError error;
    int replyBufferId;
    int bufferId;
    TRKBuffer* buffer;
    TRKBuffer* replyBuffer;

    error = TRKGetFreeBuffer(&bufferId, &buffer);

    if (error == DS_NoError) {
        error = TRKAppendBuffer1_ui8(buffer, DSMSG_PositionFile);
    }

    if (error == DS_NoError) {
        error = TRKAppendBuffer1_ui32(buffer, replyErr);
    }

    if (error == DS_NoError) {
        error = TRKAppendBuffer1_ui32(buffer, param_2);
    }

    if (error == DS_NoError) {
        error = TRKAppendBuffer1_ui8(buffer, param_3);
    }

    if (error == DS_NoError) {
        *ioResult = DS_IONoError;
        error = TRKRequestSend(buffer, &replyBufferId, 3, 3, 0);

        if (error == DS_NoError) {
            replyBuffer = TRKGetBuffer(replyBufferId);
            TRKSetBufferPosition(replyBuffer, 2);
        }

        if (error == DS_NoError) {
            error = TRKReadBuffer1_ui8(replyBuffer, ioResult);
        }

        TRKReleaseBuffer(replyBufferId);
    }

    TRKReleaseBuffer(bufferId);
    return error;
}
