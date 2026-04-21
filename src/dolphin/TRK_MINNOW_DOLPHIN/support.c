/* TODO: restore stripped imported address metadata if needed. */

#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/support.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msg.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msgbuf.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/msghndlr.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/serpoll.h"
#include <string.h>

DSError TRKSuppAccessFile(u32 file_handle, u8* data, size_t* count, u8* io_result,
                          BOOL need_reply, BOOL read) {
    DSError error;
    int replyBufferId;
    TRKBuffer* replyBuffer;
    int bufferId;
    TRKBuffer* buffer;
    u32 length;
    u32 done;
    u8 replyIOResult;
    u16 replyLength;
    BOOL exit;

    if (data == NULL || *count == 0) {
        return DS_ParameterError;
    }

    exit = FALSE;
    *io_result = DS_IONoError;
    done = 0;
    error = DS_NoError;
    while (!exit && done < *count && error == DS_NoError && *io_result == DS_IONoError) {
        if (*count - done > 0x800) {
            length = 0x800;
        } else {
            length = *count - done;
        }

        error = TRKGetFreeBuffer(&bufferId, &buffer);

        if (error == DS_NoError) {
            int command;

            command = DSMSG_WriteFile;
            if (read) {
                command = DSMSG_ReadFile;
            }

            error = TRKAppendBuffer1_ui8(buffer, command);
        }

        if (error == DS_NoError) {
            error = TRKAppendBuffer1_ui32(buffer, file_handle);
        }

        if (error == DS_NoError) {
            error = TRKAppendBuffer1_ui16(buffer, length);
        }

        if (!read && error == DS_NoError) {
            error = TRKAppendBuffer_ui8(buffer, data + done, length);
        }

        if (error == DS_NoError) {
            if (need_reply) {
                int wait_for_reply;

                replyLength = 0;
                replyIOResult = DS_IONoError;
                wait_for_reply = 0;

                if (read && file_handle == 0) {
                    wait_for_reply = 1;
                }

                error = TRKRequestSend(buffer, &replyBufferId, 5, 3,
                                       wait_for_reply == 0);
                if (error == DS_NoError) {
                    replyBuffer = TRKGetBuffer(replyBufferId);
                    TRKSetBufferPosition(replyBuffer, 2);
                }

                if (error == DS_NoError) {
                    error = TRKReadBuffer1_ui8(replyBuffer, &replyIOResult);
                }

                if (error == DS_NoError) {
                    error = TRKReadBuffer1_ui16(replyBuffer, &replyLength);
                }

                if (read && error == DS_NoError) {
                    if (replyBuffer->length != replyLength + 5) {
                        replyLength = replyBuffer->length - 5;
                        if (replyIOResult == DS_IONoError) {
                            replyIOResult = DS_IOError;
                        }
                    }

                    if (replyLength <= length) {
                        error = TRKReadBuffer_ui8(replyBuffer, data + done,
                                                  replyLength);
                    }
                }

                if (replyLength != length) {
                    if ((!read || replyLength >= length)
                        && replyIOResult == DS_IONoError) {
                        replyIOResult = DS_IOError;
                    }
                    length = replyLength;
                    exit = TRUE;
                }

                *io_result = replyIOResult;
                TRKReleaseBuffer(replyBufferId);
            } else {
                error = TRKMessageSend((TRK_Msg*)buffer);
            }
        }

        TRKReleaseBuffer(bufferId);
        done += length;
    }

    *count = done;
    return error;
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
