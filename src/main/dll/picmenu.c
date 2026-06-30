/*
 * picmenu - THP movie-load and decode back-end: movieLoad, audio DMA init,
 * reader/decoder threads.
 *
 * Drives the front-end attract/demo movies, which are THP files streamed
 * from disc. movieLoad() opens the file (singleton player at lbl_803A5D60),
 * validates the THP magic/version, and parses the per-frame component table
 * (video and optional audio). AttractMovieAudio_Init/Shutdown manage the AI
 * DMA audio path and its double-buffered DMA ring.
 *
 * Two worker threads carry the pipeline:
 *   - the reader (THPRead_Reader, CreateReadThread) DVD-reads each frame's
 *     bytes into free buffers and hands them to the decoder via message
 *     queues, wrapping back to the movie data offset when a looping movie
 *     hits its last frame;
 *   - the video decoder (AttractMovieVideo_Decoder / ...ForOnMemory,
 *     CreateVideoDecodeThread) THPVideoDecode()s each frame into a Y/U/V
 *     texture set and posts it for display.
 * The on-memory decoder variant walks an in-RAM movie image directly
 * instead of consuming reader messages.
 *
 * The PushReadedBuffer2 / Pop* / PushFree* helpers are the message-queue
 * plumbing between the reader, decoder, and display sides.
 */
#include "dolphin/ai.h"
#include "main/dll/FRONT/attract_movie.h"
#include "dolphin/thp/THPPlayer.h"
#include "string.h"
extern int DVDRead(void* fileInfo, void* buf, int size, int offset);
extern s32 THPVideoDecode(void* file, void* tileY, void* tileU, void* tileV, void* work);
extern void AttractMovieAudio_DmaCallback(void);
extern char lbl_803A57C0[0x50C];
extern char gPicMenuReadThreadArea[0x1000];
extern OSThread gPicMenuReadThread;
extern OSMessageQueue gPicMenuReadedBuffer2Queue;
extern OSMessageQueue gPicMenuReadedBufferQueue;
extern OSMessageQueue gPicMenuFreeReadBufferQueue;
extern char gPicMenuVideoDecodeThreadArea[0x18];
extern OSMessageQueue gPicMenuDecodedTextureSetQueue;
extern OSMessageQueue gPicMenuFreeTextureSetQueue;
extern OSThread gPicMenuVideoDecodeThread;
extern char gPicMenuDvdReadBuffer[0x40];
extern char sPicMenuThpMagic;
extern f32 gPicMenuMaxVolume;
extern s32 lbl_803DD660;
extern AIDCallback lbl_803DD668;
extern s32 lbl_803DD66C;
extern u32 lbl_803DD670;
extern u32 lbl_803DD674;
extern u32 lbl_803DD678;
extern s32 gPicMenuReadThreadCreated; /* sbss slot is 8 bytes; upper word unreferenced */
extern s32 gPicMenuVideoDecodeThreadCreated;
extern s32 gPicMenuVideoDecodePrepareReady;
extern u32 gAttractMovieIdleFrameCount; /* sbss slot is 8 bytes; upper word unreferenced */

void THPRead_Reader(void);
void AttractMovieVideo_DecoderForOnMemory(void*);
void AttractMovieVideo_Decoder(void);

#define THP_VERSION_1_0 0x10000

/* per-frame component kinds in THPHeader::mCompInfoDataOffsets table */
enum {
    THP_COMPONENT_VIDEO = 0,
    THP_COMPONENT_AUDIO = 1
};

BOOL movieLoad(const char* fileName, void* onMemory)
{
    AttractMovieAudioInfo* audioInfo;
    AttractMovieVideoInfo* videoInfo;
    char* pb; /* holds the isOpen read/write only; other accesses use the raw global */
    THPFrameCompInfo* compInfo;
    u32 readOff;
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

    result = DVDRead((DVDFileInfo*)&lbl_803A5D60, gPicMenuDvdReadBuffer, 0x40, 0);
    if (result < 0)
    {
        DVDClose((DVDFileInfo*)&lbl_803A5D60);
        return 0;
    }

    memcpy(&((AttractMoviePlayer*)&lbl_803A5D60)->header, gPicMenuDvdReadBuffer,
           sizeof(((AttractMoviePlayer*)&lbl_803A5D60)->header));

    if (strcmp(((AttractMoviePlayer*)&lbl_803A5D60)->header.mMagic, &sPicMenuThpMagic) != 0)
    {
        DVDClose((DVDFileInfo*)&lbl_803A5D60);
        return 0;
    }

    if (((AttractMoviePlayer*)&lbl_803A5D60)->header.mVersion != THP_VERSION_1_0)
    {
        DVDClose((DVDFileInfo*)&lbl_803A5D60);
        return 0;
    }

    {
        u32 compOff = ((AttractMoviePlayer*)&lbl_803A5D60)->header.mCompInfoDataOffsets;

        result = DVDRead((DVDFileInfo*)&lbl_803A5D60, gPicMenuDvdReadBuffer, 0x20, compOff);
        if (result < 0)
        {
            DVDClose((DVDFileInfo*)&lbl_803A5D60);
            return 0;
        }

        compInfo = &((AttractMoviePlayer*)&lbl_803A5D60)->compInfo;
        memcpy(compInfo, gPicMenuDvdReadBuffer, sizeof(*compInfo));
        readOff = compOff + sizeof(*compInfo);
        ((AttractMoviePlayer*)&lbl_803A5D60)->audioExists = 0;
    }

    for (i = 0; i < compInfo->mNumComponents; i++)
    {
        switch (((AttractMoviePlayer*)&lbl_803A5D60)->compInfo.mFrameComp[i])
        {
        case THP_COMPONENT_VIDEO:
            result = DVDRead((DVDFileInfo*)&lbl_803A5D60, gPicMenuDvdReadBuffer, 0x20, readOff);
            if (result < 0)
            {
                DVDClose((DVDFileInfo*)&lbl_803A5D60);
                return 0;
            }
            memcpy(videoInfo, gPicMenuDvdReadBuffer, sizeof(*videoInfo));
            readOff += sizeof(*videoInfo);
            break;
        case THP_COMPONENT_AUDIO:
            result = DVDRead((DVDFileInfo*)&lbl_803A5D60, gPicMenuDvdReadBuffer, 0x20, readOff);
            if (result < 0)
            {
                DVDClose((DVDFileInfo*)&lbl_803A5D60);
                return 0;
            }
            memcpy(audioInfo, gPicMenuDvdReadBuffer, sizeof(*audioInfo));
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
    ((AttractMoviePlayer*)&lbl_803A5D60)->isOnMemory = (s32)onMemory;
    ((AttractMoviePlayer*)pb)->isOpen = 1;
    ((AttractMoviePlayer*)&lbl_803A5D60)->curVolume = gPicMenuMaxVolume;
    ((AttractMoviePlayer*)&lbl_803A5D60)->targetVolume = gPicMenuMaxVolume;
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
    u32 saved;
    AIDCallback oldCb;
    register AIDCallback dmaCallback;

    memset((AttractMoviePlayer*)((char*)(int)lbl_803A57C0 + 0x5A0), 0, sizeof(AttractMoviePlayer));
    OSInitMessageQueue((OSMessageQueue*)((char*)(int)lbl_803A57C0 + 0x50C),
                       (void*)((char*)(int)lbl_803A57C0 + ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES), 3);

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
        memset((char*)(int)lbl_803A57C0, 0, ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES);
        DCFlushRange((char*)(int)lbl_803A57C0, ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES);
        AIInitDMA((u32)((char*)(int)lbl_803A57C0 + lbl_803DD678 * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE),
                  ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        AIStartDMA();
    }

    lbl_803DD660 = 1;
    return 1;
}

void PushReadedBuffer2(OSMessage msg)
{
    OSSendMessage(&gPicMenuReadedBuffer2Queue, msg, OS_MESSAGE_BLOCK);
}

#pragma dont_inline on
OSMessage PopReadedBuffer2(void)
{
    OSMessage msg;
    OSReceiveMessage(&gPicMenuReadedBuffer2Queue, &msg, OS_MESSAGE_BLOCK);
    return msg;
}
#pragma dont_inline reset

#pragma dont_inline on
void PushFreeReadBuffer(OSMessage msg)
{
    OSSendMessage(&gPicMenuFreeReadBufferQueue, msg, OS_MESSAGE_BLOCK);
}
#pragma dont_inline reset

#pragma dont_inline on
OSMessage PopReadedBuffer(void)
{
    OSMessage msg;
    OSReceiveMessage(&gPicMenuReadedBufferQueue, &msg, OS_MESSAGE_BLOCK);
    return msg;
}
#pragma dont_inline reset

void THPRead_Reader(void)
{
    AttractMoviePlayer* player = (AttractMoviePlayer*)&lbl_803A5D60;
    int i = 0;
    char* base = gPicMenuReadThreadArea;
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
    if (gPicMenuReadThreadCreated != 0)
    {
        OSCancelThread(&gPicMenuReadThread);
        gPicMenuReadThreadCreated = 0;
    }
}

void ReadThreadStart(void)
{
    if (gPicMenuReadThreadCreated != 0)
    {
        OSResumeThread(&gPicMenuReadThread);
    }
}

BOOL CreateReadThread(OSPriority priority)
{
    char* base = gPicMenuReadThreadArea;
    char* stack = base + 0x1000;

    if (!OSCreateThread((OSThread*)stack, (void*(*)(void*))THPRead_Reader, NULL,
                        stack, 0x1000, priority, 1))
    {
        return 0;
    }

    OSInitMessageQueue((OSMessageQueue*)(base + 0x13C8), (void*)(base + 0x1360), 10);
    OSInitMessageQueue((OSMessageQueue*)(base + 0x13A8), (void*)(base + 0x1338), 10);
    OSInitMessageQueue((OSMessageQueue*)(base + 0x1388), (void*)(base + 0x1310), 10);
    gPicMenuReadThreadCreated = 1;
    return 1;
}

OSMessage PopDecodedTextureSet(s32 flags)
{
    OSMessage msg;
    if (OSReceiveMessage(&gPicMenuDecodedTextureSetQueue, &msg, flags) == 1)
    {
        return msg;
    }
    return (OSMessage)0;
}

void PushFreeTextureSet(OSMessage msg)
{
    OSSendMessage(&gPicMenuFreeTextureSetQueue, msg, OS_MESSAGE_NOBLOCK);
}

void AttractMovieVideo_Decode(void* param)
{
    AttractMoviePlayer* player;
    char* db;
    u32 i;
    char* dvdData;
    u32* compSizes;

    db = gPicMenuVideoDecodeThreadArea;
    compSizes = (u32*)(((AttractMovieReadBuffer*)param)->ptr + 8);
    player = &lbl_803A5D60;
    dvdData = (char*)((AttractMovieReadBuffer*)param)->ptr +
        player->compInfo.mNumComponents * sizeof(u32) + 8;

    {
        AttractMoviePlayer* player2;
        u8* componentKind;
        void** readMsg;
        OSMessage tmpBuf;

        OSReceiveMessage((OSMessageQueue*)(db + 0x38), &tmpBuf, OS_MESSAGE_BLOCK);
        readMsg = tmpBuf;
        i = 0;
        player2 = &lbl_803A5D60;
        componentKind = (u8*)player2;

        while (i < player->compInfo.mNumComponents)
        {
            switch (componentKind[0x70])
            {
            case THP_COMPONENT_VIDEO:
            {
                s32 dec = THPVideoDecode(dvdData,
                                         ((AttractMovieTextureSet*)readMsg)->yTexture,
                                         ((AttractMovieTextureSet*)readMsg)->uTexture,
                                         ((AttractMovieTextureSet*)readMsg)->vTexture,
                                         player2->thpWorkArea);
                player2->videoError = dec;
                if (dec != 0)
                {
                    if (gPicMenuVideoDecodePrepareReady != 0)
                    {
                        PrepareReady(0);
                        gPicMenuVideoDecodePrepareReady = 0;
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
                break;
            }
            }
            dvdData += *compSizes;
            compSizes++;
            componentKind++;
            i++;
        }
    }

    if (gPicMenuVideoDecodePrepareReady != 0)
    {
        PrepareReady(1);
        gPicMenuVideoDecodePrepareReady = 0;
    }
}

void AttractMovieVideo_DecoderForOnMemory(void* param)
{
    AttractMoviePlayer* player = &lbl_803A5D60;
    u32 frameSize = player->frameStride;
    void* cur = param;
    int i = 0;

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
                    u32 sum = i + bOff;
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
            u32 sum = i + bOff;
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
                    OSSuspendThread(&gPicMenuVideoDecodeThread);
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
    AttractMoviePlayer* player = &lbl_803A5D60;
    void* msg;

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
            msg = PopReadedBuffer();
        }
        AttractMovieVideo_Decode(msg);
        PushFreeReadBuffer((OSMessage)msg);
    }
}

void VideoDecodeThreadCancel(void)
{
    if (gPicMenuVideoDecodeThreadCreated != 0)
    {
        OSCancelThread(&gPicMenuVideoDecodeThread);
        gPicMenuVideoDecodeThreadCreated = 0;
    }
}

void VideoDecodeThreadStart(void)
{
    if (gPicMenuVideoDecodeThreadCreated != 0)
    {
        OSResumeThread(&gPicMenuVideoDecodeThread);
    }
}

#pragma peephole on
BOOL CreateVideoDecodeThread(OSPriority priority, u32 onMemoryArg)
{
    char* db = gPicMenuVideoDecodeThreadArea;

    if (onMemoryArg != 0)
    {
        if (!OSCreateThread((OSThread*)(db + 0x1058), (void*(*)(void*))AttractMovieVideo_DecoderForOnMemory,
                            (void*)onMemoryArg,
                            (void*)(db + 0x1058), 0x1000, priority, 1))
        {
            return 0;
        }
    }
    else
    {
        if (!OSCreateThread((OSThread*)(db + 0x1058), (void*(*)(void*))AttractMovieVideo_Decoder, NULL,
                            (void*)(db + 0x1058), 0x1000, priority, 1))
        {
            return 0;
        }
    }

    OSInitMessageQueue((OSMessageQueue*)(db + 0x38), (void*)(db + 0x0C), 3);
    OSInitMessageQueue((OSMessageQueue*)(db + 0x18), db, 3);
    gPicMenuVideoDecodeThreadCreated = 1;
    gPicMenuVideoDecodePrepareReady = 1;
    return 1;
}
#pragma peephole reset
