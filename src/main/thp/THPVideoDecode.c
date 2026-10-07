/*
 * THPVideoDecode - attract-movie video decoder thread and message queues.
 */
#include "main/thp_video_decode.h"
#include "main/thp_read.h"
#include "main/thp_player.h"
#include "dolphin/os/OSInterrupt.h"
#include "dolphin/os/OSThread.h"
#include "dolphin/thp/THPDecode.h"

#define THP_VIDEO_BUFFER_COUNT 3
#define THP_VIDEO_STACK_SIZE   0x1000

enum {
    THP_COMPONENT_VIDEO = 0,
    THP_PLAY_LOOP = 1
};

OSThread gAttractMovieVideoThread;
char gAttractMovieVideoThreadStack[THP_VIDEO_STACK_SIZE];
OSMessageQueue gAttractMovieVideoFreeTextureSetQueue;
OSMessageQueue gAttractMovieVideoDecodedTextureSetQueue;
OSMessage gAttractMovieVideoFreeMessages[THP_VIDEO_BUFFER_COUNT];
OSMessage gAttractMovieVideoDecodedMessages[THP_VIDEO_BUFFER_COUNT];

s32 gAttractMovieIdleFrameCount;
s32 gAttractMovieVideoPrepareReady;
s32 gAttractMovieVideoThreadCreated;

static void* AttractMovieVideo_Decoder(void* unused);
static void* AttractMovieVideo_DecoderForOnMemory(void* firstFrame);
static void AttractMovieVideo_Decode(AttractMovieReadBuffer* readBuffer);

BOOL CreateVideoDecodeThread(OSPriority priority, void* onMemoryData) {
    if (onMemoryData != 0) {
        if (!OSCreateThread(&gAttractMovieVideoThread, AttractMovieVideo_DecoderForOnMemory, onMemoryData,
                            gAttractMovieVideoThreadStack + sizeof(gAttractMovieVideoThreadStack), THP_VIDEO_STACK_SIZE,
                            priority, 1)) {
            return 0;
        }
    } else {
        if (!OSCreateThread(&gAttractMovieVideoThread, AttractMovieVideo_Decoder, NULL,
                            gAttractMovieVideoThreadStack + sizeof(gAttractMovieVideoThreadStack), THP_VIDEO_STACK_SIZE,
                            priority, 1)) {
            return 0;
        }
    }

    OSInitMessageQueue(&gAttractMovieVideoFreeTextureSetQueue, gAttractMovieVideoFreeMessages, THP_VIDEO_BUFFER_COUNT);
    OSInitMessageQueue(&gAttractMovieVideoDecodedTextureSetQueue, gAttractMovieVideoDecodedMessages,
                       THP_VIDEO_BUFFER_COUNT);
    gAttractMovieVideoThreadCreated = 1;
    gAttractMovieVideoPrepareReady = 1;
    return 1;
}

void VideoDecodeThreadStart(void) {
    if (gAttractMovieVideoThreadCreated != 0) {
        OSResumeThread(&gAttractMovieVideoThread);
    }
}

void VideoDecodeThreadCancel(void) {
    if (gAttractMovieVideoThreadCreated != 0) {
        OSCancelThread(&gAttractMovieVideoThread);
        gAttractMovieVideoThreadCreated = 0;
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
                    u32 frameCount = player->header.mNumFrames;
                    u32 initialFrame = player->initReadFrame;
                    u32 movieFrame = ((u32)msg->frameNumber + initialFrame) % frameCount;
                    if (movieFrame == frameCount - 1 && !(player->playFlags & THP_PLAY_LOOP)) {
                        AttractMovieVideo_Decode(msg);
                    }
                }
                PushFreeReadBuffer(msg);
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
        PushFreeReadBuffer(msg);
    }
}

static void* AttractMovieVideo_DecoderForOnMemory(void* firstFrame) {
    AttractMoviePlayer* player = &gAttractMoviePlayer;
    u32 frameSize = player->initReadSize;
    AttractMovieReadBuffer readBuffer;
    int i;

    readBuffer.ptr = firstFrame;
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
                    u32 frameCount;
                    u32 initialFrame = player->initReadFrame;
                    u32 frameWithOffset = i + initialFrame;
                    u32 movieFrame = frameWithOffset % (frameCount = player->header.mNumFrames);
                    if (movieFrame == frameCount - 1) {
                        if (!(player->playFlags & THP_PLAY_LOOP)) {
                            break; /* movieFrame==frameCount-1, not looping: go to decode */
                        }
                        frameSize = *(u32*)readBuffer.ptr;
                        readBuffer.ptr = player->movieData;
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
            u32 frameCount;
            u32 initialFrame = player->initReadFrame;
            u32 frameWithOffset = i + initialFrame;
            u32 movieFrame = frameWithOffset % (frameCount = player->header.mNumFrames);
            if (movieFrame == frameCount - 1) {
                if (player->playFlags & THP_PLAY_LOOP) {
                    frameSize = *(u32*)readBuffer.ptr;
                    readBuffer.ptr = player->movieData;
                } else {
                    OSSuspendThread(&gAttractMovieVideoThread);
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

static void AttractMovieVideo_Decode(AttractMovieReadBuffer* readBuffer) {
    AttractMoviePlayer* player;
    AttractMoviePlayer* decodePlayer;
    AttractMovieTextureSet* textureSet;
    u8* playerCursor;
    u32 i;
    u32* componentSizes;
    char* componentData;
    OSMessage message;

    componentSizes = (u32*)(readBuffer->ptr + 8);
    player = &gAttractMoviePlayer;

    componentData = (char*)readBuffer->ptr + player->compInfo.mNumComponents * sizeof(u32) + 8;
    OSReceiveMessage(&gAttractMovieVideoFreeTextureSetQueue, &message, OS_MESSAGE_BLOCK);
    textureSet = message;
    i = 0;
    decodePlayer = &gAttractMoviePlayer;
    playerCursor = (u8*)decodePlayer;

    while (i < player->compInfo.mNumComponents) {
        switch (playerCursor[offsetof(AttractMoviePlayer, compInfo.mFrameComp)]) {
        case THP_COMPONENT_VIDEO: {
            s32 decodeResult = THPVideoDecode(componentData, textureSet->yTexture, textureSet->uTexture,
                                              textureSet->vTexture, decodePlayer->thpWorkArea);
            decodePlayer->videoError = decodeResult;
            if (decodeResult != 0) {
                if (gAttractMovieVideoPrepareReady != 0) {
                    PrepareReady(0);
                    gAttractMovieVideoPrepareReady = 0;
                }
                OSSuspendThread(&gAttractMovieVideoThread);
            }
            textureSet->frameNumber = readBuffer->frameNumber;
            OSSendMessage(&gAttractMovieVideoDecodedTextureSetQueue, (OSMessage)textureSet, OS_MESSAGE_BLOCK);
            {
                u32 intr = OSDisableInterrupts();
                decodePlayer->videoDecodeCount++;
                OSRestoreInterrupts(intr);
            }
            gAttractMovieIdleFrameCount = 0;
            break;
        }
        }
        componentData += *componentSizes;
        componentSizes++;
        playerCursor++;
        i++;
    }

    if (gAttractMovieVideoPrepareReady != 0) {
        PrepareReady(1);
        gAttractMovieVideoPrepareReady = 0;
    }
}

void PushFreeTextureSet(OSMessage msg) {
    OSSendMessage(&gAttractMovieVideoFreeTextureSetQueue, msg, OS_MESSAGE_NOBLOCK);
}

OSMessage PopDecodedTextureSet(s32 flags) {
    OSMessage msg;
    if (OSReceiveMessage(&gAttractMovieVideoDecodedTextureSetQueue, &msg, flags) == 1) {
        return msg;
    }
    return (OSMessage)0;
}
