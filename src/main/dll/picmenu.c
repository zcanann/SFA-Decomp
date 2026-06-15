#include "dolphin/ai.h"
#include "main/dll/FRONT/attract_movie.h"
#include "dolphin/thp/THPPlayer.h"
#include "string.h"

extern s32 DVDRead(DVDFileInfo* fileInfo, void* addr, s32 length, s32 offset);
extern s32 THPVideoDecode(void* file, void* tileY, void* tileU, void* tileV, void* work);

extern void AttractMovieAudio_DmaCallback(void);

extern char lbl_803A57C0[0x50C];
extern char lbl_803A5F08[0x1000];
extern OSThread lbl_803A6F08;
extern OSMessageQueue lbl_803A7290;
extern OSMessageQueue lbl_803A72B0;
extern OSMessageQueue lbl_803A72D0;
extern char lbl_803A72F0[0x18];
extern OSMessageQueue lbl_803A7308;
extern OSMessageQueue lbl_803A7328;
extern OSThread lbl_803A8348;
extern char lbl_803A5D20[0x40];

extern char lbl_803DB9E8;

extern f32 lbl_803E1D54;

extern s32 lbl_803DD660;
extern AIDCallback lbl_803DD668;
extern s32 lbl_803DD66C;
extern u32 lbl_803DD670;
extern u32 lbl_803DD674;
extern u32 lbl_803DD678;
extern s32 lbl_803DD688;
extern s32 lbl_803DD690;
extern s32 lbl_803DD694;
extern u32 gAttractMovieIdleFrameCount;

void THPRead_Reader(void);
void AttractMovieVideo_DecoderForOnMemory(void*);
void AttractMovieVideo_Decoder(void);

BOOL movieLoad(const char* fileName, void* param2)
{
    AttractMovieAudioInfo* audioInfo; /* r28 */
    AttractMovieVideoInfo* videoInfo; /* r29 */
    char* pb; /* r30 */
    THPFrameCompInfo* compInfo; /* r25 */
    u32 readOff; /* r24 */
    s32 result;
    u32 i;

    if (lbl_803DD660 == 0)
    {
        return 0;
    }

    pb = (char*)&lbl_803A5D60;

    if (((AttractMoviePlayer*)pb)->isOpen != 0)
    {
        return 0;
    }

    videoInfo = &((AttractMoviePlayer*)pb)->videoInfo;
    memset(videoInfo, 0, sizeof(*videoInfo));
    audioInfo = &((AttractMoviePlayer*)&lbl_803A5D60)->audioInfo;
    memset(audioInfo, 0, sizeof(*audioInfo));

    if (!DVDOpen(fileName, (DVDFileInfo*)&lbl_803A5D60))
    {
        return 0;
    }

    result = DVDRead((DVDFileInfo*)&lbl_803A5D60, lbl_803A5D20, 0x40, 0);
    if (result < 0)
    {
        DVDClose((DVDFileInfo*)&lbl_803A5D60);
        return 0;
    }

    memcpy(&((AttractMoviePlayer*)&lbl_803A5D60)->header, lbl_803A5D20,
           sizeof(((AttractMoviePlayer*)&lbl_803A5D60)->header));

    if (strcmp(((AttractMoviePlayer*)&lbl_803A5D60)->header.mMagic, &lbl_803DB9E8) != 0)
    {
        DVDClose((DVDFileInfo*)&lbl_803A5D60);
        return 0;
    }

    if (((AttractMoviePlayer*)&lbl_803A5D60)->header.mVersion != 0x10000)
    {
        DVDClose((DVDFileInfo*)&lbl_803A5D60);
        return 0;
    }

    {
        u32 compOff = ((AttractMoviePlayer*)&lbl_803A5D60)->header.mCompInfoDataOffsets;

        result = DVDRead((DVDFileInfo*)&lbl_803A5D60, lbl_803A5D20, 0x20, compOff);
        if (result < 0)
        {
            DVDClose((DVDFileInfo*)&lbl_803A5D60);
            return 0;
        }

        compInfo = &((AttractMoviePlayer*)&lbl_803A5D60)->compInfo;
        memcpy(compInfo, lbl_803A5D20, sizeof(*compInfo));
        readOff = compOff + sizeof(*compInfo);
        ((AttractMoviePlayer*)&lbl_803A5D60)->audioExists = 0;
    }

    for (i = 0; i < compInfo->mNumComponents; i++)
    {
        switch (((AttractMoviePlayer*)&lbl_803A5D60)->compInfo.mFrameComp[i])
        {
        case 0:
            result = DVDRead((DVDFileInfo*)&lbl_803A5D60, lbl_803A5D20, 0x20, readOff);
            if (result < 0)
            {
                DVDClose((DVDFileInfo*)&lbl_803A5D60);
                return 0;
            }
            memcpy(videoInfo, lbl_803A5D20, sizeof(*videoInfo));
            readOff += sizeof(*videoInfo);
            break;
        case 1:
            result = DVDRead((DVDFileInfo*)&lbl_803A5D60, lbl_803A5D20, 0x20, readOff);
            if (result < 0)
            {
                DVDClose((DVDFileInfo*)&lbl_803A5D60);
                return 0;
            }
            memcpy(audioInfo, lbl_803A5D20, sizeof(*audioInfo));
            ((AttractMoviePlayer*)&lbl_803A5D60)->audioExists = 1;
            readOff += sizeof(*audioInfo);
            break;
        default:
            return 0;
        }
    }

    ((AttractMoviePlayer*)&lbl_803A5D60)->internalState = 0;
    ((AttractMoviePlayer*)&lbl_803A5D60)->state = 0;
    ((AttractMoviePlayer*)&lbl_803A5D60)->playFlags = 0;
    ((AttractMoviePlayer*)&lbl_803A5D60)->movieData = param2;
    ((AttractMoviePlayer*)pb)->isOpen = 1;
    ((AttractMoviePlayer*)&lbl_803A5D60)->curVolume = lbl_803E1D54;
    ((AttractMoviePlayer*)&lbl_803A5D60)->targetVolume = lbl_803E1D54;
    ((AttractMoviePlayer*)&lbl_803A5D60)->rampCount = 0;

    return 1;
}

void AttractMovieAudio_Shutdown(void)
{
    u32 saved = OSDisableInterrupts();
    if (lbl_803DD668 != (AIDCallback)0)
    {
        AIRegisterDMACallback(lbl_803DD668);
    }
    OSRestoreInterrupts(saved);
    lbl_803DD660 = 0;
}

BOOL AttractMovieAudio_Init(int audioMode)
{
    register char* base;
    u32 saved;
    AIDCallback oldCb;
    register AIDCallback dmaCallback;

    base = (char*)(int)lbl_803A57C0;
    memset((AttractMoviePlayer*)(base + 0x5A0), 0, sizeof(AttractMoviePlayer));
    OSInitMessageQueue((OSMessageQueue*)(base + 0x50C), (void*)(base + ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES), 3);

    if (!THPInit())
    {
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

    if (oldCb == (AIDCallback)0)
    {
        if (lbl_803DD66C != 0)
        {
            AIRegisterDMACallback((AIDCallback)0);
            OSRestoreInterrupts(saved);
            return 0;
        }
    }

    OSRestoreInterrupts(saved);

    if (lbl_803DD66C == 0)
    {
        memset(base, 0, ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES);
        DCFlushRange(base, ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES);
        AIInitDMA((u32)(base + lbl_803DD678 * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE),
                  ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        AIStartDMA();
    }

    lbl_803DD660 = 1;
    return 1;
}

void PushReadedBuffer2(OSMessage msg)
{
    OSSendMessage(&lbl_803A7290, msg, OS_MESSAGE_BLOCK);
}

#pragma dont_inline on
OSMessage PopReadedBuffer2(void)
{
    OSMessage msg;
    OSReceiveMessage(&lbl_803A7290, &msg, OS_MESSAGE_BLOCK);
    return msg;
}
#pragma dont_inline reset

#pragma dont_inline on
void PushFreeReadBuffer(OSMessage msg)
{
    OSSendMessage(&lbl_803A72D0, msg, OS_MESSAGE_BLOCK);
}
#pragma dont_inline reset

#pragma dont_inline on
OSMessage PopReadedBuffer(void)
{
    OSMessage msg;
    OSReceiveMessage(&lbl_803A72B0, &msg, OS_MESSAGE_BLOCK);
    return msg;
}
#pragma dont_inline reset

void THPRead_Reader(void)
{
    char* base = lbl_803A5F08;
    int i = 0;
    AttractMoviePlayer* player = (AttractMoviePlayer*)(int)&lbl_803A5D60;
    AttractMovieReadBuffer* req;
    u32 readOff = player->initOffset;
    u32 readSize = player->initReadSize;

    while (1)
    {
        OSMessage msgVal;
        s32 res;

        OSReceiveMessage((OSMessageQueue*)(base + 0x13C8), &msgVal, OS_MESSAGE_BLOCK);
        req = (AttractMovieReadBuffer*)msgVal;

        res = DVDReadPrio(&player->fileInfo, req->ptr, readSize, readOff, 2);
        if (res != (s32)readSize)
        {
            if (res == -1)
            {
                player->dvdError = -1;
            }
            if (i == 0)
            {
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
            u32 pos = (i + bOff) % cols;
            if (pos == cols - 1)
            {
                if (player->playFlags & 1)
                {
                    readOff = player->header.mMovieDataOffsets;
                }
                else
                {
                    OSSuspendThread((OSThread*)(base + 0x1000));
                }
            }
        }
        i++;
    }
}

void ReadThreadCancel(void)
{
    if (lbl_803DD688 != 0)
    {
        OSCancelThread(&lbl_803A6F08);
        lbl_803DD688 = 0;
    }
}

void ReadThreadStart(void)
{
    if (lbl_803DD688 != 0)
    {
        OSResumeThread(&lbl_803A6F08);
    }
}

BOOL CreateReadThread(OSPriority priority)
{
    char* base = lbl_803A5F08;
    char* stack = base + 0x1000;

    if (!OSCreateThread((OSThread*)stack, (void*(*)(void*))THPRead_Reader, NULL,
                        stack, 0x1000, priority, 1))
    {
        return 0;
    }

    OSInitMessageQueue((OSMessageQueue*)(base + 0x13C8), (void*)(base + 0x1360), 10);
    OSInitMessageQueue((OSMessageQueue*)(base + 0x13A8), (void*)(base + 0x1338), 10);
    OSInitMessageQueue((OSMessageQueue*)(base + 0x1388), (void*)(base + 0x1310), 10);
    lbl_803DD688 = 1;
    return 1;
}

OSMessage PopDecodedTextureSet(s32 flags)
{
    OSMessage msg;
    if (OSReceiveMessage(&lbl_803A7308, &msg, flags) == 1)
    {
        return msg;
    }
    return (OSMessage)0;
}

void PushFreeTextureSet(OSMessage msg)
{
    OSSendMessage(&lbl_803A7328, msg, OS_MESSAGE_NOBLOCK);
}

void AttractMovieVideo_Decode(void* param)
{
    AttractMoviePlayer* player; /* 1st function-scope callee-saved → r31 */
    char* db; /* 2nd → r30 */
    u32 i; /* 3rd → r29 */
    u32* compSizes; /* 4th → r28 */
    char* dvdData; /* 5th → r27 */

    db = lbl_803A72F0;
    compSizes = (u32*)(((AttractMovieReadBuffer*)param)->ptr + 8);
    player = &lbl_803A5D60;
    dvdData = (char*)((AttractMovieReadBuffer*)param)->ptr +
        player->compInfo.mNumComponents * sizeof(u32) + 8;

    {
        AttractMoviePlayer* player2; /* block-local → r25 */
        void** readMsg; /* block-local → r24 */
        char* componentKind; /* block-local → r23 */
        OSMessage tmpBuf;

        OSReceiveMessage((OSMessageQueue*)(db + 0x38), &tmpBuf, OS_MESSAGE_BLOCK);
        readMsg = (void**)tmpBuf;
        i = 0;
        player2 = player;
        componentKind = (char*)player2;

        while (i < player->compInfo.mNumComponents)
        {
            if (componentKind[0x70] == 0)
            {
                s32 dec = THPVideoDecode(dvdData,
                                         ((AttractMovieTextureSet*)readMsg)->yTexture,
                                         ((AttractMovieTextureSet*)readMsg)->uTexture,
                                         ((AttractMovieTextureSet*)readMsg)->vTexture,
                                         player2->thpWorkArea);
                player2->videoError = dec;
                if (dec != 0)
                {
                    if (lbl_803DD694 != 0)
                    {
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
                gAttractMovieIdleFrameCount = 0;
            }
            dvdData += *compSizes;
            compSizes++;
            componentKind++;
            i++;
        }
    }

    if (lbl_803DD694 != 0)
    {
        PrepareReady(1);
        lbl_803DD694 = 0;
    }
}

void AttractMovieVideo_DecoderForOnMemory(void* param)
{
    AttractMoviePlayer* player = &lbl_803A5D60; /* r31 */
    u32 frameSize = player->frameStride; /* r30 */
    void* cur = param; /* at stack[8], address taken by &cur */
    int i = 0; /* r29 */

    while (1)
    {
        if (player->audioExists != 0)
        {
            while (player->videoDecodeCount < 0)
            {
                {
                    u32 intr = OSDisableInterrupts();
                    player->videoDecodeCount += 1;
                    OSRestoreInterrupts(intr);
                }
                {
                    u32 cols;
                    u32 bOff = player->initReadFrame;
                    u32 sum = (u32)i + bOff;
                    u32 pos = sum % (cols = player->header.mNumFrames);
                    if (pos == cols - 1)
                    {
                        if (!(player->playFlags & 1))
                        {
                            break; /* pos==cols-1, not looping: go to decode */
                        }
                        frameSize = *(u32*)cur;
                        cur = player->loopFrame;
                    }
                    else
                    {
                        u32 nextSize = *(u32*)cur;
                        cur = (char*)cur + frameSize;
                        frameSize = nextSize;
                    }
                }
                i++;
            }
        }

        *(s32*)(&cur + 1) = i;
        AttractMovieVideo_Decode(&cur);

        {
            u32 cols;
            u32 bOff = player->initReadFrame;
            u32 sum = (u32)i + bOff;
            u32 pos = sum % (cols = player->header.mNumFrames);
            if (pos == cols - 1)
            {
                if (player->playFlags & 1)
                {
                    frameSize = *(u32*)cur;
                    cur = player->loopFrame;
                }
                else
                {
                    OSSuspendThread(&lbl_803A8348);
                }
            }
            else
            {
                u32 nextSize = *(u32*)cur;
                cur = (char*)cur + frameSize;
                frameSize = nextSize;
            }
        }
        i++;
    }
}

void AttractMovieVideo_Decoder(void)
{
    AttractMoviePlayer* player = &lbl_803A5D60; /* r31 */
    void* msg; /* r30 */

    while (1)
    {
        if (player->audioExists != 0)
        {
            while (player->videoDecodeCount < 0)
            {
                msg = PopReadedBuffer2();
                {
                    u32 cols = player->header.mNumFrames;
                    u32 bOff = player->initReadFrame;
                    u32 pos = (*(u32*)((char*)msg + 4) + bOff) % cols;
                    if (pos == cols - 1 && !(player->playFlags & 1))
                    {
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
        if (player->audioExists != 0)
        {
            msg = PopReadedBuffer2();
        }
        else
        {
            msg = (void*)PopReadedBuffer();
        }
        AttractMovieVideo_Decode(msg);
        PushFreeReadBuffer((OSMessage)msg);
    }
}

void VideoDecodeThreadCancel(void)
{
    if (lbl_803DD690 != 0)
    {
        OSCancelThread(&lbl_803A8348);
        lbl_803DD690 = 0;
    }
}

void VideoDecodeThreadStart(void)
{
    if (lbl_803DD690 != 0)
    {
        OSResumeThread(&lbl_803A8348);
    }
}

#pragma peephole on
BOOL CreateVideoDecodeThread(OSPriority param_1, u32 param_2)
{
    char* db = lbl_803A72F0;

    if (param_2 != 0)
    {
        if (!OSCreateThread((OSThread*)(db + 0x1058), (void*(*)(void*))AttractMovieVideo_DecoderForOnMemory,
                            (void*)param_2,
                            (void*)(db + 0x1058), 0x1000, param_1, 1))
        {
            return 0;
        }
    }
    else
    {
        if (!OSCreateThread((OSThread*)(db + 0x1058), (void*(*)(void*))AttractMovieVideo_Decoder, NULL,
                            (void*)(db + 0x1058), 0x1000, param_1, 1))
        {
            return 0;
        }
    }

    OSInitMessageQueue((OSMessageQueue*)(db + 0x38), (void*)(db + 0x0C), 3);
    OSInitMessageQueue((OSMessageQueue*)(db + 0x18), (void*)db, 3);
    lbl_803DD690 = 1;
    lbl_803DD694 = 1;
    return 1;
}
