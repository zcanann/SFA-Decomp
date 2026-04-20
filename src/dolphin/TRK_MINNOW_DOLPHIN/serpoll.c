/* TODO: restore stripped imported address metadata if needed. */

#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/serpoll.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/nubevent.h"
#include "PowerPC_EABI_Support/MetroTRK/trk.h"

static TRKFramingState gTRKFramingState;

void* gTRKInputPendingPtr;

MessageBufferID TRKTestForPacket(void) {
    s32 result;
    s32 err;
    u8 c;
    s32 msgBufID;
    TRKBuffer* buffer;

    result = 0;
    err = TRKReadUARTPoll(&c);
    while (err == 0 && result == 0) {
        if (gTRKFramingState.receiveState != DSRECV_InFrame) {
            gTRKFramingState.isEscape = FALSE;
        }

        switch (gTRKFramingState.receiveState) {
            case DSRECV_Wait:
                if ((s8)c == 0x7E) {
                    result = TRKGetFreeBuffer(&gTRKFramingState.msgBufID, &gTRKFramingState.buffer);
                    gTRKFramingState.fcsType = 0;
                    gTRKFramingState.receiveState = DSRECV_Found;
                }
                break;

            case DSRECV_Found:
                if ((s8)c == 0x7E) {
                    break;
                }
                gTRKFramingState.receiveState = DSRECV_InFrame;

            case DSRECV_InFrame:
                if ((s8)c == 0x7E) {
                    BOOL packetComplete;

                    if (gTRKFramingState.isEscape) {
                        TRKStandardACK(gTRKFramingState.buffer, DSMSG_ReplyNAK, DSREPLY_EscapeError);
                        if (gTRKFramingState.msgBufID != -1) {
                            TRKReleaseBuffer(gTRKFramingState.msgBufID);
                            gTRKFramingState.msgBufID = -1;
                        }
                        gTRKFramingState.buffer = NULL;
                        gTRKFramingState.receiveState = DSRECV_Wait;
                        break;
                    }

                    buffer = gTRKFramingState.buffer;
                    if (buffer->length < 2) {
                        TRKStandardACK(buffer, DSMSG_ReplyNAK, DSREPLY_PacketSizeError);
                        if (gTRKFramingState.msgBufID != -1) {
                            TRKReleaseBuffer(gTRKFramingState.msgBufID);
                            gTRKFramingState.msgBufID = -1;
                        }
                        gTRKFramingState.buffer = NULL;
                        gTRKFramingState.receiveState = DSRECV_Wait;
                        packetComplete = FALSE;
                    } else {
                        buffer->position = 0;
                        buffer->length--;
                        packetComplete = TRUE;
                    }

                    if (packetComplete) {
                        msgBufID = gTRKFramingState.msgBufID;
                        gTRKFramingState.msgBufID = -1;
                        gTRKFramingState.buffer = NULL;
                        gTRKFramingState.receiveState = DSRECV_Wait;
                        return msgBufID;
                    }

                    gTRKFramingState.receiveState = DSRECV_Wait;
                } else {
                    if (gTRKFramingState.isEscape) {
                        c ^= 0x20;
                        gTRKFramingState.isEscape = FALSE;
                    } else if ((s8)c == 0x7D) {
                        gTRKFramingState.isEscape = TRUE;
                        break;
                    }

                    buffer = gTRKFramingState.buffer;
                    if (buffer->position >= 0x880) {
                        result = DS_MessageBufferOverflow;
                    } else {
                        buffer->data[buffer->position++] = c;
                        buffer->length++;
                        result = DS_NoError;
                    }
                    gTRKFramingState.fcsType += c;
                }
                break;

            case DSRECV_FrameOverflow:
                if ((s8)c == 0x7E) {
                    if (gTRKFramingState.msgBufID != -1) {
                        TRKReleaseBuffer(gTRKFramingState.msgBufID);
                        gTRKFramingState.msgBufID = -1;
                    }
                    gTRKFramingState.buffer = NULL;
                    gTRKFramingState.receiveState = DSRECV_Wait;
                }
                break;
        }

        err = TRKReadUARTPoll(&c);
    }

    return -1;
}

void TRKGetInput(void) {
    TRKBuffer* msgBuffer;
    TRKEvent event;
    int id;
    u8 command;

    id = TRKTestForPacket();
    if (id == -1) {
        return;
    }

    msgBuffer = TRKGetBuffer(id);
    TRKSetBufferPosition(msgBuffer, 0);
    TRKReadBuffer1_ui8(msgBuffer, &command);
    if (command < DSMSG_ReplyACK) {
        TRKConstructEvent(&event, NUBEVENT_Request);
        gTRKFramingState.msgBufID = -1;
        event.msgBufID = id;
        TRKPostEvent(&event);
    } else {
        TRKReleaseBuffer(id);
    }
}

void TRKProcessInput(int bufferIdx) {
    TRKEvent event;

    TRKConstructEvent(&event, NUBEVENT_Request);
    gTRKFramingState.msgBufID = -1;
    event.msgBufID = bufferIdx;
    TRKPostEvent(&event);
}

DSError TRKInitializeSerialHandler(void) {
    gTRKFramingState.msgBufID = -1;
    gTRKFramingState.receiveState = DSRECV_Wait;
    gTRKFramingState.isEscape = FALSE;

    return DS_NoError;
}

DSError TRKTerminateSerialHandler(void) {
    return DS_NoError;
}
