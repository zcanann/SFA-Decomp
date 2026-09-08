/*
 * THPVideoDecode - attract-movie video decoder thread and message queues.
 */
#include "main/thp_video_decode.h"
#include "main/dll/FRONT/attract_movie.h"
#include "main/dll/FRONT/picmenu.h"
#include "dolphin/os/OSInterrupt.h"
#include "dolphin/os/OSThread.h"
#include "dolphin/thp/THPDecode.h"
#include "dolphin/thp/THPPlayer.h"

enum
{
    THP_COMPONENT_VIDEO = 0
};

AttractMovieVideoMessageStorage gAttractMovieVideoMessages;

extern OSMessageQueue gPicMenuDecodedTextureSetQueue;
extern OSMessageQueue gPicMenuFreeTextureSetQueue;
extern OSThread gPicMenuVideoDecodeThread;

/* Layout view of the separate globals addressed through the retail BSS base. */
typedef struct AttractMovieVideoDecodeLayout {
    AttractMovieVideoMessageStorage messages;
    OSMessageQueue decodedQueue;
    OSMessageQueue freeQueue;
    u8 stack[THP_VIDEO_STACK_SIZE];
    OSThread thread;
} AttractMovieVideoDecodeLayout;

STATIC_ASSERT(sizeof(AttractMovieVideoDecodeLayout) == 0x1368);
STATIC_ASSERT(offsetof(AttractMovieVideoDecodeLayout, decodedQueue) == 0x18);
STATIC_ASSERT(offsetof(AttractMovieVideoDecodeLayout, freeQueue) == 0x38);
STATIC_ASSERT(offsetof(AttractMovieVideoDecodeLayout, stack) == 0x58);
STATIC_ASSERT(offsetof(AttractMovieVideoDecodeLayout, thread) == 0x1058);

s32 gAttractMovieIdleFrameCount;
s32 gPicMenuVideoDecodePrepareReady;
s32 gPicMenuVideoDecodeThreadCreated;

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

static void AttractMovieVideo_Decode(AttractMovieReadBuffer* readBuffer) {
    AttractMoviePlayer* player;
    char* db;
    AttractMoviePlayer* player2;
    AttractMovieTextureSet* textureSet;
    u8* componentKind;
    u32 i;
    u32* componentSizes;
    char* componentData;
    OSMessage tmpBuf;

    db = (char*)&gAttractMovieVideoMessages;
    componentSizes = (u32*)(readBuffer->ptr + 8);
    player = &gAttractMoviePlayer;

    componentData = (char*)readBuffer->ptr + player->compInfo.mNumComponents * sizeof(u32) + 8;
    OSReceiveMessage((OSMessageQueue*)(db + offsetof(AttractMovieVideoDecodeLayout, freeQueue)), &tmpBuf, OS_MESSAGE_BLOCK);
    textureSet = tmpBuf;
    i = 0;
    player2 = &gAttractMoviePlayer;
    componentKind = (u8*)player2;

    while (i < player->compInfo.mNumComponents) {
        switch (componentKind[offsetof(AttractMoviePlayer, compInfo.mFrameComp)]) {
        case THP_COMPONENT_VIDEO: {
            s32 dec = THPVideoDecode(componentData, textureSet->yTexture,
                                     textureSet->uTexture,
                                     textureSet->vTexture, player2->thpWorkArea);
            player2->videoError = dec;
            if (dec != 0) {
                if (gPicMenuVideoDecodePrepareReady != 0) {
                    PrepareReady(0);
                    gPicMenuVideoDecodePrepareReady = 0;
                }
                OSSuspendThread((OSThread*)(db + offsetof(AttractMovieVideoDecodeLayout, thread)));
            }
            textureSet->frameNumber = readBuffer->frameNumber;
            OSSendMessage((OSMessageQueue*)(db + offsetof(AttractMovieVideoDecodeLayout, decodedQueue)), (OSMessage)textureSet, OS_MESSAGE_BLOCK);
            {
                u32 intr = OSDisableInterrupts();
                player2->videoDecodeCount++;
                OSRestoreInterrupts(intr);
            }
            gAttractMovieIdleFrameCount = 0;
            break;
        }
        }
        componentData += *componentSizes;
        componentSizes++;
        componentKind++;
        i++;
    }

    if (gPicMenuVideoDecodePrepareReady != 0) {
        PrepareReady(1);
        gPicMenuVideoDecodePrepareReady = 0;
    }
}

static void* AttractMovieVideo_DecoderForOnMemory(void* param) {
    AttractMoviePlayer* player = &gAttractMoviePlayer;
    u32 frameSize = player->frameStride;
    AttractMovieReadBuffer readBuffer;
    int i;

    readBuffer.ptr = param;
    i = 0;

    while (1) {
        if (player->audioExists != 0) {
            while (player->videoDecodeCount < 0) {
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
                    if (pos == cols - 1) {
                        if (!(player->playFlags & 1)) {
                            break; /* pos==cols-1, not looping: go to decode */
                        }
                        frameSize = *(u32*)readBuffer.ptr;
                        readBuffer.ptr = player->loopFrame;
                    } else {
                        u32 nextSize = *(u32*)readBuffer.ptr;
                        readBuffer.ptr = readBuffer.ptr + frameSize;
                        frameSize = nextSize;
                    }
                }
                i++;
            }
        }

        readBuffer.frameNumber = i;
        AttractMovieVideo_Decode(&readBuffer);

        {
            u32 cols;
            u32 bOff = player->initReadFrame;
            u32 sum = i + bOff;
            u32 pos = sum % (cols = player->header.mNumFrames);
            if (pos == cols - 1) {
                if (player->playFlags & 1) {
                    frameSize = *(u32*)readBuffer.ptr;
                    readBuffer.ptr = player->loopFrame;
                } else {
                    OSSuspendThread(&gPicMenuVideoDecodeThread);
                }
            } else {
                u32 nextSize = *(u32*)readBuffer.ptr;
                readBuffer.ptr = readBuffer.ptr + frameSize;
                frameSize = nextSize;
            }
        }
        i++;
    }
}

static void* AttractMovieVideo_Decoder(void* unused) {
    AttractMoviePlayer* player = &gAttractMoviePlayer;
    AttractMovieReadBuffer* msg;

    while (1) {
        if (player->audioExists != 0) {
            while (player->videoDecodeCount < 0) {
                msg = PopReadedBuffer2();
                {
                    u32 cols = player->header.mNumFrames;
                    u32 bOff = player->initReadFrame;
                    u32 pos = ((u32)msg->frameNumber + bOff) % cols;
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

BOOL CreateVideoDecodeThread(OSPriority priority, void* onMemoryData)
{
    char* db = (char*)&gAttractMovieVideoMessages;
    void* mbuf = db;

    if (onMemoryData != 0)
    {
        if (!OSCreateThread((OSThread*)(db + offsetof(AttractMovieVideoDecodeLayout, thread)), AttractMovieVideo_DecoderForOnMemory, onMemoryData,
                            (void*)(db + offsetof(AttractMovieVideoDecodeLayout, stack) + THP_VIDEO_STACK_SIZE), THP_VIDEO_STACK_SIZE, priority, 1))
        {
            return 0;
        }
    }
    else
    {
        if (!OSCreateThread((OSThread*)(db + offsetof(AttractMovieVideoDecodeLayout, thread)), AttractMovieVideo_Decoder, NULL, (void*)(db + offsetof(AttractMovieVideoDecodeLayout, stack) + THP_VIDEO_STACK_SIZE), THP_VIDEO_STACK_SIZE,
                            priority, 1))
        {
            return 0;
        }
    }

    OSInitMessageQueue((OSMessageQueue*)(db + offsetof(AttractMovieVideoDecodeLayout, freeQueue)), (void*)(db + offsetof(AttractMovieVideoMessageStorage, free)), THP_VIDEO_BUFFER_COUNT);
    OSInitMessageQueue((OSMessageQueue*)(db + offsetof(AttractMovieVideoDecodeLayout, decodedQueue)), mbuf, THP_VIDEO_BUFFER_COUNT);
    gPicMenuVideoDecodeThreadCreated = 1;
    gPicMenuVideoDecodePrepareReady = 1;
    return 1;
}

OSThread gPicMenuVideoDecodeThread;
char gPicMenuVideoDecodeThreadStack[THP_VIDEO_STACK_SIZE];
OSMessageQueue gPicMenuFreeTextureSetQueue;
OSMessageQueue gPicMenuDecodedTextureSetQueue;
