#include "dolphin/ai.h"
#include "dolphin/dvd.h"
#include "dolphin/os.h"
#include "main/dll/FRONT/attract_movie.h"
#include "dolphin/thp/THPPlayer.h"
#include "string.h"

/* DVDRead: sync DVD read (distinct from DVDReadPrio) */
extern s32 DVDRead(DVDFileInfo* fileInfo, void* addr, s32 length, s32 offset);
extern s32 THPVideoDecode(void* file, void* tileY, void* tileU, void* tileV, void* work);

/* External functions */
extern BOOL THPInit(void);
extern void AttractMovieAudio_DmaCallback(void);

/* BSS objects (lis+addi addressing) */
extern char             lbl_803A57C0[0x50C];
extern char             lbl_803A5F08[0x1000];
extern OSThread         lbl_803A6F08;
extern OSMessageQueue   lbl_803A7290;
extern OSMessageQueue   lbl_803A72B0;
extern OSMessageQueue   lbl_803A72D0;
extern char             lbl_803A72F0[0x18];
extern OSMessageQueue   lbl_803A7308;
extern OSMessageQueue   lbl_803A7328;
extern OSThread         lbl_803A8348;
extern char             lbl_803A5D20[0x40];

/* SDATA string (SDA21) */
extern char             lbl_803DB9E8[];

/* Float constant (sdata2) */
extern f32              lbl_803E1D54;

/* SBSS dword flags (SDA21) */
extern s32              lbl_803DD660;
extern AIDCallback      lbl_803DD668;
extern s32              lbl_803DD66C;
extern u32              lbl_803DD670;
extern u32              lbl_803DD674;
extern u32              lbl_803DD678;
extern s32              lbl_803DD688;
extern s32              lbl_803DD690;
extern s32              lbl_803DD694;
extern u32              lbl_803DD698;

/* Forward declarations needed by OSCreateThread */
void  THPRead_Reader(void);
void  AttractMovieVideo_DecoderForOnMemory(void*);
void  AttractMovieVideo_Decoder(void);

/* ------------------------------------------------------------------ */
/* movieLoad (748 bytes)                                                */
/* ------------------------------------------------------------------ */
#pragma scheduling off
BOOL movieLoad(const char* fileName, void* param2)
{
    char* pb; /* r30 */
    AttractMovieVideoInfo* videoInfo; /* r29 */
    AttractMovieAudioInfo* audioInfo; /* r28 */
    THPFrameCompInfo* compInfo; /* r25 */
    u32 readOff;      /* r24 */
    s32 result;
    u32 i;

    if (lbl_803DD660 == 0) {
        return 0;
    }

    pb = (char*)&lbl_803A5D60;

    if (((AttractMoviePlayer*)pb)->isOpen != 0) {
        return 0;
    }

    videoInfo = &((AttractMoviePlayer*)pb)->videoInfo;
    memset(videoInfo, 0, sizeof(*videoInfo));
    audioInfo = &((AttractMoviePlayer*)pb)->audioInfo;
    memset(audioInfo, 0, sizeof(*audioInfo));

    if (!DVDOpen(fileName, (DVDFileInfo*)pb)) {
        return 0;
    }

    result = DVDRead((DVDFileInfo*)pb, lbl_803A5D20, 0x40, 0);
    if (result < 0) {
        DVDClose((DVDFileInfo*)pb);
        return 0;
    }

    memcpy(&((AttractMoviePlayer*)pb)->header, lbl_803A5D20, sizeof(((AttractMoviePlayer*)pb)->header));

    if (strcmp(((AttractMoviePlayer*)pb)->header.mMagic, lbl_803DB9E8) != 0) {
        DVDClose((DVDFileInfo*)pb);
        return 0;
    }

    if (((AttractMoviePlayer*)pb)->header.mVersion != 0x10000) {
        DVDClose((DVDFileInfo*)pb);
        return 0;
    }

    {
        u32 compOff = ((AttractMoviePlayer*)pb)->header.mCompInfoDataOffsets;

        result = DVDRead((DVDFileInfo*)pb, lbl_803A5D20, 0x20, compOff);
        if (result < 0) {
            DVDClose((DVDFileInfo*)pb);
            return 0;
        }

        compInfo = &((AttractMoviePlayer*)pb)->compInfo;
        memcpy(compInfo, lbl_803A5D20, sizeof(*compInfo));
        readOff = compOff + sizeof(*compInfo);
        ((AttractMoviePlayer*)pb)->audioExists = 0;
    }

    for (i = 0; i < compInfo->mNumComponents; i++) {
        if (compInfo->mFrameComp[i] == 1) {
            result = DVDRead((DVDFileInfo*)pb, lbl_803A5D20, 0x20, readOff);
            if (result < 0) {
                DVDClose((DVDFileInfo*)pb);
                return 0;
            }
            memcpy(audioInfo, lbl_803A5D20, sizeof(*audioInfo));
            ((AttractMoviePlayer*)pb)->audioExists = 1;
            readOff += sizeof(*audioInfo);
        } else if (compInfo->mFrameComp[i] == 0) {
            result = DVDRead((DVDFileInfo*)pb, lbl_803A5D20, 0x20, readOff);
            if (result < 0) {
                DVDClose((DVDFileInfo*)pb);
                return 0;
            }
            memcpy(videoInfo, lbl_803A5D20, sizeof(*videoInfo));
            readOff += sizeof(*videoInfo);
        } else {
            return 0;
        }
    }

    ((AttractMoviePlayer*)pb)->internalState = 0;
    ((AttractMoviePlayer*)pb)->state = 0;
    ((AttractMoviePlayer*)pb)->playFlags = 0;
    ((AttractMoviePlayer*)pb)->movieData = param2;
    ((AttractMoviePlayer*)pb)->isOpen = 1;
    ((AttractMoviePlayer*)pb)->curVolume = lbl_803E1D54;
    ((AttractMoviePlayer*)pb)->targetVolume = lbl_803E1D54;
    ((AttractMoviePlayer*)pb)->rampCount = 0;

    return 1;
}
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* AttractMovieAudio_Shutdown (76 bytes)                               */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void AttractMovieAudio_Shutdown(void)
{
    u32 saved = OSDisableInterrupts();
    if (lbl_803DD668 != (AIDCallback)0) {
        AIRegisterDMACallback(lbl_803DD668);
    }
    OSRestoreInterrupts(saved);
    lbl_803DD660 = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* AttractMovieAudio_Init (288 bytes)                                  */
/* ------------------------------------------------------------------ */
#pragma scheduling off
BOOL AttractMovieAudio_Init(int audioMode)
{
    register char* base;
    u32 saved;
    AIDCallback oldCb;
    register AIDCallback dmaCallback;

    base = lbl_803A57C0;
    memset((AttractMoviePlayer*)(base + 0x5A0), 0, sizeof(AttractMoviePlayer));
    OSInitMessageQueue((OSMessageQueue*)(base + 0x50C), (void*)(base + ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES), 3);

    if (!THPInit()) {
        return 0;
    }

    saved = OSDisableInterrupts();
    lbl_803DD66C = audioMode;
    lbl_803DD678 = 0;
    lbl_803DD674 = 0;
    lbl_803DD670 = 0;
    dmaCallback = AttractMovieAudio_DmaCallback;
    oldCb = AIRegisterDMACallback(dmaCallback);
    lbl_803DD668 = oldCb;

    if (oldCb == (AIDCallback)0) {
        if (lbl_803DD66C != 0) {
            AIRegisterDMACallback((AIDCallback)0);
            OSRestoreInterrupts(saved);
            return 0;
        }
    }

    OSRestoreInterrupts(saved);

    if (lbl_803DD66C == 0) {
        memset(base, 0, ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES);
        DCFlushRange(base, ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES);
        AIInitDMA((u32)(base + lbl_803DD678 * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE), ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        AIStartDMA();
    }

    lbl_803DD660 = 1;
    return 1;
}
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* PushReadedBuffer2 (48 bytes)                                        */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void PushReadedBuffer2(OSMessage msg)
{
    OSSendMessage(&lbl_803A7290, msg, OS_MESSAGE_BLOCK);
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* PopReadedBuffer2 (52 bytes)                                         */
/* ------------------------------------------------------------------ */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
OSMessage PopReadedBuffer2(void)
{
    OSMessage msg;
    OSReceiveMessage(&lbl_803A7290, &msg, OS_MESSAGE_BLOCK);
    return msg;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/* ------------------------------------------------------------------ */
/* PushFreeReadBuffer (48 bytes)                                       */
/* ------------------------------------------------------------------ */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void PushFreeReadBuffer(OSMessage msg)
{
    OSSendMessage(&lbl_803A72D0, msg, OS_MESSAGE_BLOCK);
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/* ------------------------------------------------------------------ */
/* PopReadedBuffer (52 bytes)                                          */
/* ------------------------------------------------------------------ */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
OSMessage PopReadedBuffer(void)
{
    OSMessage msg;
    OSReceiveMessage(&lbl_803A72B0, &msg, OS_MESSAGE_BLOCK);
    return msg;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/* ------------------------------------------------------------------ */
/* THPRead_Reader (248 bytes) - DVD-read thread                        */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void THPRead_Reader(void)
{
    char* base = lbl_803A5F08;
    int i = 0;
    AttractMoviePlayer* player = &lbl_803A5D60;
    AttractMovieReadBuffer* req;
    u32 readOff = player->initOffset;
    u32 readSize = player->initReadSize;

    while (1) {
        OSMessage msgVal;
        s32 res;

        OSReceiveMessage((OSMessageQueue*)(base + 0x13C8), &msgVal, OS_MESSAGE_BLOCK);
        req = (AttractMovieReadBuffer*)msgVal;

        res = DVDReadPrio(&player->fileInfo, req->ptr, readSize, readOff, 2);
        if (res != (s32)readSize) {
            if (res == -1) {
                player->dvdError = -1;
            }
            if (i == 0) {
                PrepareReady(0);
            }
            OSSuspendThread((OSThread*)(base + 0x1000));
        }

        req->frameNumber = i;
        OSSendMessage((OSMessageQueue*)(base + 0x13A8), (OSMessage)req, OS_MESSAGE_BLOCK);

        readOff += readSize;
        readSize = *(u32*)req->ptr;

        {
            u32 cols = player->header.mNumFrames;
            u32 bOff = player->initReadFrame;
            u32 pos  = (i + bOff) % cols;
            if (pos == cols - 1) {
                if (player->playFlags & 1) {
                    readOff = player->header.mMovieDataOffsets;
                } else {
                    OSSuspendThread((OSThread*)(base + 0x1000));
                }
            }
        }
        i++;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* ReadThreadCancel (60 bytes)                                         */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void ReadThreadCancel(void)
{
    if (lbl_803DD688 != 0) {
        OSCancelThread(&lbl_803A6F08);
        lbl_803DD688 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* ReadThreadStart (52 bytes)                                          */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void ReadThreadStart(void)
{
    if (lbl_803DD688 != 0) {
        OSResumeThread(&lbl_803A6F08);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* CreateReadThread (156 bytes)                                        */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
BOOL CreateReadThread(OSPriority priority)
{
    char* base = lbl_803A5F08;
    char* stack = base + 0x1000;

    if (!OSCreateThread((OSThread*)stack, (void*(*)(void*))THPRead_Reader, NULL,
                        stack, 0x1000, priority, 1)) {
        return 0;
    }

    OSInitMessageQueue((OSMessageQueue*)(base + 0x13C8), (void*)(base + 0x1360), 10);
    OSInitMessageQueue((OSMessageQueue*)(base + 0x13A8), (void*)(base + 0x1338), 10);
    OSInitMessageQueue((OSMessageQueue*)(base + 0x1388), (void*)(base + 0x1310), 10);
    lbl_803DD688 = 1;
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* PopDecodedTextureSet (68 bytes)                                     */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
OSMessage PopDecodedTextureSet(s32 flags)
{
    OSMessage msg;
    if (OSReceiveMessage(&lbl_803A7308, &msg, flags) == 1) {
        return msg;
    }
    return (OSMessage)0;
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* PushFreeTextureSet (48 bytes)                                       */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void PushFreeTextureSet(OSMessage msg)
{
    OSSendMessage(&lbl_803A7328, msg, OS_MESSAGE_NOBLOCK);
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* AttractMovieVideo_Decode (328 bytes) - video decode frame           */
/* ------------------------------------------------------------------ */
#pragma scheduling off
void AttractMovieVideo_Decode(void* param)
{
    AttractMoviePlayer* player; /* 1st function-scope callee-saved → r31 */
    char* db;           /* 2nd → r30 */
    u32 i;              /* 3rd → r29 */
    u32* compSizes;     /* 4th → r28 */
    char* dvdData;      /* 5th → r27 */
    /* param (function arg) → r26 auto */

    db = lbl_803A72F0;
    compSizes = (u32*)(((AttractMovieReadBuffer*)param)->ptr + 8);
    player = &lbl_803A5D60;
    dvdData = (char*)((AttractMovieReadBuffer*)param)->ptr +
              player->compInfo.mNumComponents * sizeof(u32) + 8;

    {
        AttractMoviePlayer* player2; /* block-local → r25 */
        void** readMsg;     /* block-local → r24 */
        u8* componentKind;   /* block-local → r23 */
        OSMessage tmpBuf;

        OSReceiveMessage((OSMessageQueue*)(db + 0x38), &tmpBuf, OS_MESSAGE_BLOCK);
        readMsg = (void**)tmpBuf;
        i = 0;
        player2 = &lbl_803A5D60;
        componentKind = player2->compInfo.mFrameComp;

        while (i < player->compInfo.mNumComponents) {
            if (*componentKind == 0) {
                s32 dec = THPVideoDecode(dvdData,
                                         ((AttractMovieTextureSet*)readMsg)->yTexture,
                                         ((AttractMovieTextureSet*)readMsg)->uTexture,
                                         ((AttractMovieTextureSet*)readMsg)->vTexture,
                                         player2->thpWorkArea);
                player2->videoError = dec;
                if (dec != 0) {
                    if (lbl_803DD694 != 0) {
                        PrepareReady(0);
                        lbl_803DD694 = 0;
                    }
                    OSSuspendThread((OSThread*)(db + 0x1058));
                }
                ((AttractMovieTextureSet*)readMsg)->frameNumber =
                    ((AttractMovieReadBuffer*)param)->frameNumber;
                OSSendMessage((OSMessageQueue*)(db + 0x18), (OSMessage)readMsg, OS_MESSAGE_BLOCK);
                {
                    u32 intr = OSDisableInterrupts();
                    player2->videoDecodeCount++;
                    OSRestoreInterrupts(intr);
                }
                lbl_803DD698 = 0;
            }
            dvdData += *compSizes;
            compSizes++;
            componentKind++;
            i++;
        }
    }

    if (lbl_803DD694 != 0) {
        PrepareReady(1);
        lbl_803DD694 = 0;
    }
}
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* AttractMovieVideo_DecoderForOnMemory (316 bytes)                    */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void AttractMovieVideo_DecoderForOnMemory(void* param)
{
    AttractMoviePlayer* player = &lbl_803A5D60; /* r31 */
    u32 frameSize = player->frameStride;        /* r30 */
    void* cur = param;                  /* at stack[8], address taken by &cur */
    int i = 0;                          /* r29 */

    while (1) {
        if (player->audioExists != 0) {
            while (player->videoDecodeCount < 0) {
                {
                    u32 intr = OSDisableInterrupts();
                    player->videoDecodeCount += 1;
                    OSRestoreInterrupts(intr);
                }
                {
                    u32 cols = player->header.mNumFrames;
                    u32 bOff = player->initReadFrame;
                    u32 sum  = (u32)i + bOff;
                    u32 pos  = sum % cols;
                    if (pos == cols - 1) {
                        if (!(player->playFlags & 1)) {
                            break; /* pos==cols-1, not looping: go to decode */
                        }
                        /* looping: update cur and frameSize */
                        frameSize = *(u32*)cur;
                        cur = player->loopFrame;
                    } else {
                        u32 nextSize = *(u32*)cur;
                        cur = (char*)cur + frameSize;
                        frameSize = nextSize;
                    }
                }
                i++;
            }
        }

        /* Store i adjacent to cur on stack so AttractMovieVideo_Decode can read it as param[1] */
        *(s32*)(&cur + 1) = i;
        AttractMovieVideo_Decode(&cur);

        {
            u32 cols = player->header.mNumFrames;
            u32 bOff = player->initReadFrame;
            u32 sum  = (u32)i + bOff;
            u32 pos  = sum % cols;
            if (pos == cols - 1) {
                if (player->playFlags & 1) {
                    frameSize = *(u32*)cur;
                    cur = player->loopFrame;
                } else {
                    OSSuspendThread(&lbl_803A8348);
                }
            } else {
                u32 nextSize = *(u32*)cur;
                cur = (char*)cur + frameSize;
                frameSize = nextSize;
            }
        }
        i++;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* AttractMovieVideo_Decoder (204 bytes)                               */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void AttractMovieVideo_Decoder(void)
{
    AttractMoviePlayer* player = &lbl_803A5D60; /* r31 */
    void* msg;                         /* r30 */

    while (1) {
        if (player->audioExists != 0) {
            while (player->videoDecodeCount < 0) {
                msg = PopReadedBuffer2();
                {
                    u32 cols = player->header.mNumFrames;
                    u32 bOff = player->initReadFrame;
                    u32 pos  = (*(u32*)((char*)msg + 4) + bOff) % cols;
                    if (pos == cols - 1 && !(player->playFlags & 1)) {
                        AttractMovieVideo_Decode(msg);
                    }
                }
                PushFreeReadBuffer((OSMessage)msg);
                {
                    u32 intr = OSDisableInterrupts();
                    player->videoDecodeCount += 1;
                    OSRestoreInterrupts(intr);
                }
            }
        }
        if (player->audioExists != 0) {
            msg = PopReadedBuffer2();
        } else {
            msg = (void*)PopReadedBuffer();
        }
        AttractMovieVideo_Decode(msg);
        PushFreeReadBuffer((OSMessage)msg);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* VideoDecodeThreadCancel (60 bytes)                                  */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void VideoDecodeThreadCancel(void)
{
    if (lbl_803DD690 != 0) {
        OSCancelThread(&lbl_803A8348);
        lbl_803DD690 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* VideoDecodeThreadStart (52 bytes)                                   */
/* ------------------------------------------------------------------ */
#pragma scheduling off
#pragma peephole off
void VideoDecodeThreadStart(void)
{
    if (lbl_803DD690 != 0) {
        OSResumeThread(&lbl_803A8348);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* ------------------------------------------------------------------ */
/* CreateVideoDecodeThread (200 bytes)                                 */
/* ------------------------------------------------------------------ */
#pragma scheduling off
BOOL CreateVideoDecodeThread(OSPriority param_1, u32 param_2)
{
    char* db = lbl_803A72F0;

    if (param_2 != 0) {
        if (!OSCreateThread((OSThread*)(db + 0x1058), (void*(*)(void*))AttractMovieVideo_DecoderForOnMemory, (void*)param_2,
                            (void*)(db + 0x1058), 0x1000, param_1, 1)) {
            return 0;
        }
    } else {
        if (!OSCreateThread((OSThread*)(db + 0x1058), (void*(*)(void*))AttractMovieVideo_Decoder, NULL,
                            (void*)(db + 0x1058), 0x1000, param_1, 1)) {
            return 0;
        }
    }

    OSInitMessageQueue((OSMessageQueue*)(db + 0x38), (void*)(db + 0x0C), 3);
    OSInitMessageQueue((OSMessageQueue*)(db + 0x18), (void*)db, 3);
    lbl_803DD690 = 1;
    lbl_803DD694 = 1;
    return 1;
}
#pragma scheduling reset
