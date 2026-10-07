/* THP movie playback, frame presentation, and audio mixing. */
#include "main/thp_player.h"
#include <stddef.h>
#include "dolphin/ai.h"
#include "dolphin/os.h"
#include "dolphin/vi.h"
#include "main/model.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXGeometry.h"
#include "main/pi_dolphin_api.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSInterrupt.h"
#include "dolphin/os/OSMessage.h"
#include "dolphin/vi/vifuncs.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "string.h"
#include "track/intersect_depth_state_api.h"
#include "main/attract_movie_api.h"
#include "main/thp_read.h"
#include "global.h"
#include "main/fileio.h"
#include "main/audio_decode_thread.h"
#include "dolphin/thp/THPDraw.h"
#include "main/dll/FRONT/attract_movie.h"
#include "dolphin/thp/THPPlayer.h"

static const GXColorS10 sMovieTevColor0 = {-90, 0, -114, 135};
static const GXColor sMovieKColor0 = {0x00, 0x00, 0xE2, 0x58};
static const GXColor sMovieKColor1 = {0xB3, 0x00, 0x00, 0xB6};
static const GXColor sMovieKColor2 = {0xFF, 0x00, 0xFF, 0x80};

#define MOVIE_VOLUME_MAX      0x7f
#define MOVIE_FADE_FRAMES_MAX 60000
#define S16_MIN               (-0x8000)
#define S16_MAX               0x7fff

u16 gAttractMovieVolumeScale[128] = {
    0,     2,     8,     18,    32,    50,    73,    99,    130,   164,   203,   245,   292,   343,   398,   457,
    520,   587,   658,   733,   812,   895,   983,   1074,  1170,  1269,  1373,  1481,  1592,  1708,  1828,  1952,
    2080,  2212,  2348,  2488,  2632,  2781,  2933,  3090,  3250,  3415,  3583,  3756,  3933,  4114,  4298,  4487,
    4680,  4877,  5079,  5284,  5493,  5706,  5924,  6145,  6371,  6600,  6834,  7072,  7313,  7559,  7809,  8063,
    8321,  8583,  8849,  9119,  9394,  9672,  9954,  10241, 10531, 10826, 11125, 11427, 11734, 12045, 12360, 12679,
    13002, 13329, 13660, 13995, 14335, 14678, 15025, 15377, 15732, 16092, 16456, 16823, 17195, 17571, 17951, 18335,
    18723, 19115, 19511, 19911, 20316, 20724, 21136, 21553, 21974, 22398, 22827, 23260, 23696, 24137, 24582, 25031,
    25484, 25941, 26402, 26868, 27337, 27810, 28288, 28769, 29255, 29744, 30238, 30736, 31238, 31744, 32254, 32768,
};

u8 gAttractMovieLoopCompleted;
OSMessage gAttractMoviePrepareReadyMessage;
u32 gAttractMovieAudioDmaBufferIndex;
u32 gAttractMovieAudioPendingSourceAddr;
u32 gAttractMovieAudioMixSourceAddr;
s32 gAttractMovieAudioMode;
AIDCallback gAttractMovieAudioPrevDmaCallback;
static VIRetraceCallback OldVIPostCallback;
s32 gAttractMovieAudioActive;
AttractMoviePlayer gAttractMoviePlayer;
u32 gAttractMovieDvdReadBuffer[16] ALIGN_DECL(32);
OSMessageQueue gAttractMoviePrepareReadyQueue;
OSMessageQueue gAttractMovieSpentTextureSetQueue;
OSMessage gAttractMovieSpentTextureSetMessages[3];
char gAttractMovieAudioDmaBuffer[ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES];

char sAttractMovieThpMagic[] = "THP";

#define THP_VERSION_1_0      0x10000
#define ALIGN_NEXT_32(value) (((value) + 0x1f) & ~0x1f)

enum {
    THP_PLAY_LOOP = 1,
    THP_PLAY_EVEN_FIELD = 2,
    THP_PLAY_ODD_FIELD = 4
};

enum {
    THP_COMPONENT_VIDEO = 0,
    THP_COMPONENT_AUDIO = 1
};

static void AttractMovieAudio_Mix(s16* destination, s16* source, u32 sampleCount);
static void PlayControl(u32 retraceCount);
static void InitAllMessageQueue(void);

BOOL AttractMovieAudio_Init(int audioMode) {
    u32 saved;
    AIDCallback oldCb;
    register AIDCallback dmaCallback;

    memset(&gAttractMoviePlayer, 0, sizeof(AttractMoviePlayer));
    OSInitMessageQueue(&gAttractMovieSpentTextureSetQueue, gAttractMovieSpentTextureSetMessages, 3);

    if (!THPInit()) {
        return 0;
    }

    saved = OSDisableInterrupts();
    gAttractMovieAudioMode = audioMode;
    gAttractMovieAudioDmaBufferIndex = 0;
    gAttractMovieAudioPendingSourceAddr = 0;
    gAttractMovieAudioMixSourceAddr = 0;
    dmaCallback = AttractMovieAudio_DmaCallback;
    oldCb = AIRegisterDMACallback(dmaCallback);
    gAttractMovieAudioPrevDmaCallback = oldCb;

    if (oldCb == (AIDCallback)0) {
        if (gAttractMovieAudioMode != 0) {
            AIRegisterDMACallback((AIDCallback)0);
            OSRestoreInterrupts(saved);
            return 0;
        }
    }

    OSRestoreInterrupts(saved);

    if (gAttractMovieAudioMode == 0) {
        memset(gAttractMovieAudioDmaBuffer, 0, ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES);
        DCFlushRange(gAttractMovieAudioDmaBuffer, ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES);
        AIInitDMA(
            (u32)(gAttractMovieAudioDmaBuffer + gAttractMovieAudioDmaBufferIndex * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE),
            ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        AIStartDMA();
    }

    gAttractMovieAudioActive = 1;
    return 1;
}

void AttractMovieAudio_Shutdown(void) {
    u32 saved = OSDisableInterrupts();
    if (gAttractMovieAudioPrevDmaCallback != (AIDCallback)0) {
        AIRegisterDMACallback(gAttractMovieAudioPrevDmaCallback);
    }
    OSRestoreInterrupts(saved);
    gAttractMovieAudioActive = 0;
}

BOOL movieLoad(const char* fileName, BOOL onMemory) {
    u32 readOff;
    s32 result;
    u32 i;

    if (gAttractMovieAudioActive == 0) {
        return 0;
    }

    if (gAttractMoviePlayer.isOpen != 0) {
        return 0;
    }

    memset(&gAttractMoviePlayer.videoInfo, 0, sizeof(AttractMovieVideoInfo));
    memset(&gAttractMoviePlayer.audioInfo, 0, sizeof(AttractMovieAudioInfo));

    if (!DVDOpen(fileName, &gAttractMoviePlayer.fileInfo)) {
        return 0;
    }

    result = DVDRead(&gAttractMoviePlayer.fileInfo, gAttractMovieDvdReadBuffer, 0x40, 0);
    if (result < 0) {
        DVDClose(&gAttractMoviePlayer.fileInfo);
        return 0;
    }

    memcpy(&gAttractMoviePlayer.header, gAttractMovieDvdReadBuffer, sizeof(gAttractMoviePlayer.header));

    if (strcmp(gAttractMoviePlayer.header.mMagic, sAttractMovieThpMagic) != 0) {
        DVDClose(&gAttractMoviePlayer.fileInfo);
        return 0;
    }

    if (gAttractMoviePlayer.header.mVersion != THP_VERSION_1_0) {
        DVDClose(&gAttractMoviePlayer.fileInfo);
        return 0;
    }

    {
        u32 compOff = gAttractMoviePlayer.header.mCompInfoDataOffsets;

        result = DVDRead(&gAttractMoviePlayer.fileInfo, gAttractMovieDvdReadBuffer, 0x20, compOff);
        if (result < 0) {
            DVDClose(&gAttractMoviePlayer.fileInfo);
            return 0;
        }

        memcpy(&gAttractMoviePlayer.compInfo, gAttractMovieDvdReadBuffer, sizeof(THPFrameCompInfo));
        readOff = compOff + sizeof(THPFrameCompInfo);
        gAttractMoviePlayer.audioExists = 0;
    }

    for (i = 0; i < gAttractMoviePlayer.compInfo.mNumComponents; i++) {
        switch (gAttractMoviePlayer.compInfo.mFrameComp[i]) {
        case THP_COMPONENT_VIDEO:
            result = DVDRead(&gAttractMoviePlayer.fileInfo, gAttractMovieDvdReadBuffer, 0x20, readOff);
            if (result < 0) {
                DVDClose(&gAttractMoviePlayer.fileInfo);
                return 0;
            }
            memcpy(&gAttractMoviePlayer.videoInfo, gAttractMovieDvdReadBuffer, sizeof(AttractMovieVideoInfo));
            readOff += sizeof(AttractMovieVideoInfo);
            break;
        case THP_COMPONENT_AUDIO:
            result = DVDRead(&gAttractMoviePlayer.fileInfo, gAttractMovieDvdReadBuffer, 0x20, readOff);
            if (result < 0) {
                DVDClose(&gAttractMoviePlayer.fileInfo);
                return 0;
            }
            memcpy(&gAttractMoviePlayer.audioInfo, gAttractMovieDvdReadBuffer, sizeof(AttractMovieAudioInfo));
            gAttractMoviePlayer.audioExists = 1;
            readOff += sizeof(AttractMovieAudioInfo);
            break;
        default:
            return 0;
        }
    }

    gAttractMoviePlayer.internalState = 0;
    gAttractMoviePlayer.state = 0;
    gAttractMoviePlayer.playFlags = 0;
    gAttractMoviePlayer.isOnMemory = onMemory;
    gAttractMoviePlayer.isOpen = 1;
    gAttractMoviePlayer.curVolume = 127.0f;
    gAttractMoviePlayer.targetVolume = 127.0f;
    gAttractMoviePlayer.rampCount = 0;

    return 1;
}

int AttractMovie_CloseFile(void) {
    AttractMoviePlayer* player;

    player = &gAttractMoviePlayer;
    if ((player->isOpen != 0) && (player->state == 0)) {
        player->isOpen = 0;
        DVDClose(&player->fileInfo);
        return 1;
    }

    return 0;
}

void AttractMovie_GetBufferSizes(u32* movieOrReadBufferSize, int* yTextureBufferSize, int* uTextureBufferSize,
                                 int* vTextureBufferSize, u32* audioBufferSize, int* thpWorkBufferSize) {
    AttractMoviePlayer* player;
    u32 movieOrReadSize;
    int size;

    player = &gAttractMoviePlayer;
    if (player->isOpen != 0) {
        if (player->isOnMemory != 0) {
            movieOrReadSize = ALIGN_NEXT_32(player->header.mMovieDataSize);
        } else {
            movieOrReadSize = ALIGN_NEXT_32(player->header.mBufferSize) * 10;
        }
        *movieOrReadBufferSize = movieOrReadSize;
        player = &gAttractMoviePlayer;
        *yTextureBufferSize = ALIGN_NEXT_32(player->videoInfo.xSize * player->videoInfo.ySize) * 3;
        *uTextureBufferSize = ALIGN_NEXT_32((u32)(player->videoInfo.xSize * player->videoInfo.ySize) >> 2) * 3;
        *vTextureBufferSize = ALIGN_NEXT_32((u32)(player->videoInfo.xSize * player->videoInfo.ySize) >> 2) * 3;
        if (player->audioExists != 0) {
            size = ALIGN_NEXT_32(player->header.mAudioMaxSamples * 4) * 3;
        } else {
            size = 0;
        }
        *audioBufferSize = size;
        *thpWorkBufferSize = 0x1000;
        return;
    }

    *movieOrReadBufferSize = 0;
    *yTextureBufferSize = 0;
    *uTextureBufferSize = 0;
    *vTextureBufferSize = 0;
    *audioBufferSize = 0;
    *thpWorkBufferSize = 0;
}

int AttractMovie_AssignBuffers(void* movieOrReadBuffer, void* yTextureBuffer, void* uTextureBuffer,
                               void* vTextureBuffer, void* audioBuffer, void* thpWorkBuffer) {
    AttractMoviePlayer* player;
    u8* curr;
    u32 frameBufferSize;
    u32 yTextureSize;
    u32 uvTextureSize;
    u32 i;

    player = &gAttractMoviePlayer;
    if (player->isOpen != 0 && player->state == 0) {
        if (player->isOnMemory != 0) {
            player->movieData = movieOrReadBuffer;
            curr = (u8*)movieOrReadBuffer + player->header.mMovieDataSize;
        } else {
            curr = movieOrReadBuffer;
            for (i = 0; i < 10; i++) {
                player->readBuffer[i].ptr = curr;
                frameBufferSize = ALIGN_NEXT_32(player->header.mBufferSize);
                curr += frameBufferSize;
            }
        }

        player = &gAttractMoviePlayer;
        yTextureSize = ALIGN_NEXT_32(player->videoInfo.xSize * player->videoInfo.ySize);
        uvTextureSize = ALIGN_NEXT_32((player->videoInfo.xSize * player->videoInfo.ySize) >> 2);
        for (i = 0; i < 3; i++) {
            player->textureSet[i].yTexture = yTextureBuffer;
            DCInvalidateRange(curr, yTextureSize);
            player->textureSet[i].uTexture = uTextureBuffer;
            DCInvalidateRange(curr, uvTextureSize);
            player->textureSet[i].vTexture = vTextureBuffer;
            DCInvalidateRange(curr, uvTextureSize);
            curr += uvTextureSize;
        }

        player = &gAttractMoviePlayer;
        if (player->audioExists != 0) {
            player->audioBuffer[0].buffer = audioBuffer;
            player->audioBuffer[0].curPtr = audioBuffer;
            player->audioBuffer[0].validSample = 0;
            {
                u32 audioBufferSize = ALIGN_NEXT_32(player->header.mAudioMaxSamples * 4);
                u8* nextAudioBuffer = (u8*)audioBuffer + audioBufferSize;
                player->audioBuffer[1].buffer = (s16*)nextAudioBuffer;
                player->audioBuffer[1].curPtr = (s16*)nextAudioBuffer;
                player->audioBuffer[1].validSample = 0;
                nextAudioBuffer += audioBufferSize;
                player->audioBuffer[2].buffer = (s16*)nextAudioBuffer;
                player->audioBuffer[2].curPtr = (s16*)nextAudioBuffer;
                player->audioBuffer[2].validSample = 0;
            }
        }

        gAttractMoviePlayer.thpWorkArea = thpWorkBuffer;
        return 1;
    }
    return 0;
}

static void InitAllMessageQueue(void) {
    AttractMoviePlayer* player;
    s32 i;

    player = &gAttractMoviePlayer;
    if (player->isOnMemory == 0) {
        for (i = 0; i < ATTRACT_MOVIE_READ_BUFFER_COUNT; i++) {
            PushFreeReadBuffer(&player->readBuffer[i]);
        }
    }

    i = 0;
    player = &gAttractMoviePlayer;
    do {
        PushFreeTextureSet((OSMessage)&player->textureSet[i]);
        i++;
    } while (i < 3);

    if (gAttractMoviePlayer.audioExists != 0) {
        i = 0;
        do {
            PushFreeAudioBuffer((OSMessage)&player->audioBuffer[i]);
            i++;
        } while (i < 3);
    }

    OSInitMessageQueue(&gAttractMoviePrepareReadyQueue, &gAttractMoviePrepareReadyMessage, 1);
}

void PrepareReady(int ready) {
    OSSendMessage(&gAttractMoviePrepareReadyQueue, (OSMessage)(ptrdiff_t)ready, OS_MESSAGE_BLOCK);
}

BOOL prepareAttractMode(u32 movieIndex, s32 playFlags) {
    OSMessage readyMsg;
    u8* firstFrame;

    gAttractMovieLoopCompleted = 0;

    if (gAttractMoviePlayer.isOpen != 0 && gAttractMoviePlayer.state == 0) {
        if ((s32)movieIndex > 0) {
            u32 offsetTable = gAttractMoviePlayer.header.mOffsetDataOffsets;

            if (offsetTable == 0) {
                return FALSE;
            }
            if (gAttractMoviePlayer.header.mNumFrames > movieIndex) {
                if (DVDRead(&gAttractMoviePlayer.fileInfo, gAttractMovieDvdReadBuffer, 0x20,
                            offsetTable + ((movieIndex - 1) * sizeof(u32))) < 0) {
                    return FALSE;
                }

                gAttractMoviePlayer.initOffset =
                    gAttractMoviePlayer.header.mMovieDataOffsets + gAttractMovieDvdReadBuffer[0];
                gAttractMoviePlayer.initReadFrame = movieIndex;
                gAttractMoviePlayer.initReadSize = gAttractMovieDvdReadBuffer[1] - gAttractMovieDvdReadBuffer[0];
            } else {
                return FALSE;
            }
        } else {
            gAttractMoviePlayer.initOffset = gAttractMoviePlayer.header.mMovieDataOffsets;
            gAttractMoviePlayer.initReadSize = gAttractMoviePlayer.header.mFirstFrameSize;
            gAttractMoviePlayer.initReadFrame = movieIndex;
        }

        gAttractMoviePlayer.playFlags = playFlags;
        gAttractMoviePlayer.videoDecodeCount = 0;

        if (gAttractMoviePlayer.isOnMemory != 0) {
            if (DVDRead(&gAttractMoviePlayer.fileInfo, gAttractMoviePlayer.movieData,
                        gAttractMoviePlayer.header.mMovieDataSize, gAttractMoviePlayer.header.mMovieDataOffsets) < 0) {
                return FALSE;
            }
            /* Preserve the retail add/subtract order without an out-of-bounds intermediate pointer. */
            firstFrame = (u8*)((size_t)gAttractMoviePlayer.movieData + gAttractMoviePlayer.initOffset -
                               gAttractMoviePlayer.header.mMovieDataOffsets);
            CreateVideoDecodeThread(0xf, firstFrame);
            if (gAttractMoviePlayer.audioExists != 0) {
                CreateAudioDecodeThread(0xc, firstFrame);
            }
        } else {
            CreateVideoDecodeThread(0xf, 0);
            if (gAttractMoviePlayer.audioExists != 0) {
                CreateAudioDecodeThread(0xc, NULL);
            }
            CreateReadThread(8);
        }

        InitAllMessageQueue();
        VideoDecodeThreadStart();
        if (gAttractMoviePlayer.audioExists != 0) {
            AudioDecodeThreadStart();
        }
        if (gAttractMoviePlayer.isOnMemory == 0) {
            ReadThreadStart();
        }

        OSReceiveMessage(&gAttractMoviePrepareReadyQueue, &readyMsg, OS_MESSAGE_BLOCK);
        if ((ptrdiff_t)readyMsg == 0) {
            return FALSE;
        }
        gAttractMoviePlayer.state = 1;
        gAttractMoviePlayer.internalState = 0;
        gAttractMoviePlayer.curTextureSet = 0;
        gAttractMoviePlayer.curAudioBuffer = 0;
        gAttractMoviePlayer.curVideoFrameNumber = 0;
        gAttractMoviePlayer.curAudioFrameNumber = 0;
        OldVIPostCallback = VISetPostRetraceCallback(PlayControl);
        return TRUE;
    }
    return FALSE;
}

BOOL THPPlayerPlay(void) {
    if ((gAttractMoviePlayer.isOpen != 0) && ((gAttractMoviePlayer.state == 1) || (gAttractMoviePlayer.state == 4))) {
        gAttractMoviePlayer.state = 2;
        gAttractMoviePlayer.prevCount = 0;
        gAttractMoviePlayer.curCount = 0;
        gAttractMoviePlayer.retraceCount = -1;
        return TRUE;
    }
    return FALSE;
}

void THPPlayerStop(void) {
    OSMessage msg;

    if ((gAttractMoviePlayer.isOpen != 0) && (gAttractMoviePlayer.state != 0)) {
        gAttractMoviePlayer.internalState = 0;
        gAttractMoviePlayer.state = 0;
        VISetPostRetraceCallback(OldVIPostCallback);

        if (gAttractMoviePlayer.isOnMemory == 0) {
            DVDCancel((DVDCommandBlock*)&gAttractMoviePlayer.fileInfo);
            ReadThreadCancel();
        }

        VideoDecodeThreadCancel();
        if (gAttractMoviePlayer.audioExists != 0) {
            AudioDecodeThreadCancel();
        }

        while (
            ((OSReceiveMessage(&gAttractMovieSpentTextureSetQueue, &msg, OS_MESSAGE_NOBLOCK) == TRUE) ? msg : NULL) !=
            NULL) {
        }

        gAttractMoviePlayer.curVolume = gAttractMoviePlayer.targetVolume;
        gAttractMoviePlayer.rampCount = 0;
        gAttractMoviePlayer.dvdError = 0;
        gAttractMoviePlayer.videoError = 0;
    }
}

static void PlayControl(u32 retraceCount) {
    AttractMovieTextureSet* decodedTexture;
    s32 frame;
    int allowPop;
    s32 modResult;

    if (OldVIPostCallback != NULL) {
        OldVIPostCallback(retraceCount);
    }

    decodedTexture = (AttractMovieTextureSet*)-1;
    if (gAttractMoviePlayer.isOpen == 0) {
        return;
    }
    if (gAttractMoviePlayer.state != 2) {
        return;
    }
    if ((gAttractMoviePlayer.dvdError != 0) || (gAttractMoviePlayer.videoError != 0)) {
        gAttractMoviePlayer.internalState = 5;
        gAttractMoviePlayer.state = 5;
        return;
    }

    if ((gAttractMoviePlayer.retraceCount == 0) &&
        ((gAttractMoviePlayer.internalState == 0) || (gAttractMoviePlayer.internalState == 4))) {
        gAttractMoviePlayer.internalState = 2;
    }
    gAttractMoviePlayer.retraceCount++;

    if ((gAttractMoviePlayer.internalState == 0) || (gAttractMoviePlayer.internalState == 4)) {
        do {
            if ((gAttractMoviePlayer.playFlags & THP_PLAY_EVEN_FIELD) != 0) {
                if (VIGetNextField() == 0) {
                    allowPop = 1;
                    break;
                }
            } else if ((gAttractMoviePlayer.playFlags & THP_PLAY_ODD_FIELD) != 0) {
                if (VIGetNextField() == 1) {
                    allowPop = 1;
                    break;
                }
            } else {
                allowPop = 1;
                break;
            }
            allowPop = 0;
        } while (0);

        if (allowPop != 0) {
            if (gAttractMoviePlayer.audioExists != 0) {
                frame = gAttractMoviePlayer.curAudioTrack - gAttractMoviePlayer.curVideoNumber;
                if (frame <= 1) {
                    decodedTexture = (AttractMovieTextureSet*)PopDecodedTextureSet(0);
                    if (gAttractMoviePlayer.videoDecodeCount > frame) {
                        gAttractMoviePlayer.videoDecodeCount--;
                    }
                } else {
                    gAttractMoviePlayer.internalState = 2;
                }
            } else {
                decodedTexture = (AttractMovieTextureSet*)PopDecodedTextureSet(0);
                gAttractMoviePlayer.internalState = 2;
            }
        } else {
            gAttractMoviePlayer.retraceCount = -1;
        }
    } else if (ProperTimingForGettingNextFrame() != 0) {
        if (gAttractMoviePlayer.audioExists != 0) {
            frame = gAttractMoviePlayer.curAudioTrack - gAttractMoviePlayer.curVideoNumber;
            if (frame <= 1) {
                decodedTexture = (AttractMovieTextureSet*)PopDecodedTextureSet(0);
                if (gAttractMoviePlayer.videoDecodeCount > frame) {
                    gAttractMoviePlayer.videoDecodeCount--;
                }
            }
        } else {
            decodedTexture = (AttractMovieTextureSet*)PopDecodedTextureSet(0);
        }
    }

    if ((decodedTexture != NULL) && (decodedTexture != (AttractMovieTextureSet*)-1)) {
        gAttractMoviePlayer.curAudioTrack = decodedTexture->frameNumber;
        if (gAttractMoviePlayer.curTextureSet != NULL) {
            OSSendMessage(&gAttractMovieSpentTextureSetQueue, (OSMessage)gAttractMoviePlayer.curTextureSet,
                          OS_MESSAGE_NOBLOCK);
        }
        gAttractMoviePlayer.curTextureSet = decodedTexture;
    }

    if ((gAttractMoviePlayer.playFlags & THP_PLAY_LOOP) == 0) {
        if (gAttractMoviePlayer.audioExists != 0) {
            modResult = (gAttractMoviePlayer.curVideoNumber + gAttractMoviePlayer.initReadFrame) %
                        gAttractMoviePlayer.header.mNumFrames;
            if ((modResult == (gAttractMoviePlayer.header.mNumFrames - 1)) &&
                (gAttractMoviePlayer.dispTextureSet == NULL)) {
                modResult = (gAttractMoviePlayer.curAudioTrack + gAttractMoviePlayer.initReadFrame) %
                            gAttractMoviePlayer.header.mNumFrames;
                if ((modResult == (gAttractMoviePlayer.header.mNumFrames - 1)) && (decodedTexture == NULL)) {
                    gAttractMoviePlayer.internalState = 3;
                    gAttractMoviePlayer.state = 3;
                }
            }
        } else {
            u32 numFrames;
            modResult = (gAttractMoviePlayer.curAudioTrack + gAttractMoviePlayer.initReadFrame) %
                        (numFrames = gAttractMoviePlayer.header.mNumFrames);
            if ((modResult == (numFrames - 1)) && (decodedTexture == NULL)) {
                gAttractMoviePlayer.internalState = 3;
                gAttractMoviePlayer.state = 3;
            }
        }
    } else {
        u32 numFrames;
        modResult = (gAttractMoviePlayer.curAudioTrack + gAttractMoviePlayer.initReadFrame) %
                    (numFrames = gAttractMoviePlayer.header.mNumFrames);
        if (modResult == (numFrames - 1)) {
            gAttractMovieLoopCompleted = 1;
        }
    }
}

int ProperTimingForGettingNextFrame(void) {
    int frame;
    s64 tick;
    u32 field;

    if ((gAttractMoviePlayer.playFlags & 2) != 0) {
        field = VIGetNextField();
        if (field == 0) {
            return TRUE;
        }
    } else if ((gAttractMoviePlayer.playFlags & 4) != 0) {
        field = VIGetNextField();
        if (field == 1) {
            return TRUE;
        }
    } else {
        frame = (int)(100.0f * gAttractMoviePlayer.header.mFrameRate);
        if (VIGetTvFormat() == 1) {
            tick = gAttractMoviePlayer.retraceCount * frame;
            gAttractMoviePlayer.curCount = tick / 5000;
        } else {
            tick = gAttractMoviePlayer.retraceCount * frame;
            gAttractMoviePlayer.curCount = tick / 0x176a;
        }

        if (gAttractMoviePlayer.prevCount != gAttractMoviePlayer.curCount) {
            gAttractMoviePlayer.prevCount = gAttractMoviePlayer.curCount;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL AttractMovie_DrawTextureCallback(int unused, u32* modelPtr, u32 renderOpIdx) {
    AttractMovieTextureSet* textureSet;
    Shader* renderOp;

    if (modelPtr != NULL) {
        renderOp = ObjModel_GetRenderOp((ModelFileHeader*)*modelPtr, renderOpIdx);
    } else {
        renderOp = NULL;
    }

    if (((renderOp == NULL) || (renderOp->layers[0].materialId == 1)) && (gAttractMovieState == 2)) {
        textureSet = gAttractMoviePlayer.curTextureSet;
        THPPlayerDrawCurrentFrame(textureSet->yTexture, textureSet->uTexture, textureSet->vTexture,
                                  (s16)gAttractMoviePlayer.videoInfo.xSize, (s16)gAttractMoviePlayer.videoInfo.ySize);
        return TRUE;
    }
    return FALSE;
}

void AttractMovie_AddVideoTevStages(void) {
    AttractMovieTextureSet* textureSet;

    if (gAttractMovieState == 2) {
        textureSet = gAttractMoviePlayer.curTextureSet;
        addYUVVideoTevStages(textureSet->yTexture, textureSet->uTexture, textureSet->vTexture,
                             gAttractMoviePlayer.videoInfo.xSize, gAttractMoviePlayer.videoInfo.ySize);
    }
}

BOOL THPPlayerGetVideoInfo(void* dst) {
    if (gAttractMoviePlayer.isOpen != 0) {
        memcpy(dst, &gAttractMoviePlayer.videoInfo, sizeof(gAttractMoviePlayer.videoInfo));
        return TRUE;
    }
    return FALSE;
}

void THPPlayerPostDrawDone(void) {
    OSMessage msg;
    OSMessage textureSet;

    if (gAttractMovieAudioActive != 0) {
        while (TRUE) {
            if (OSReceiveMessage(&gAttractMovieSpentTextureSetQueue, &msg, OS_MESSAGE_NOBLOCK) == TRUE) {
                textureSet = msg;
            } else {
                textureSet = NULL;
            }
            if (textureSet == NULL) {
                break;
            }
            PushFreeTextureSet(textureSet);
        }
    }
}

void AttractMovieAudio_DmaCallback(void) {
    BOOL interrupts;

    if (gAttractMovieAudioMode == 0) {
        gAttractMovieAudioDmaBufferIndex ^= 1u;
        AIInitDMA((u32)(gAttractMovieAudioDmaBuffer +
                        (gAttractMovieAudioDmaBufferIndex * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE)),
                  ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        interrupts = OSEnableInterrupts();
        AttractMovieAudio_Mix((s16*)(gAttractMovieAudioDmaBuffer +
                                     (gAttractMovieAudioDmaBufferIndex * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE)),
                              NULL, ATTRACT_MOVIE_AUDIO_DMA_SAMPLE_COUNT);
        DCFlushRange(gAttractMovieAudioDmaBuffer +
                         (gAttractMovieAudioDmaBufferIndex * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE),
                     ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        OSRestoreInterrupts(interrupts);
    } else {
        if (gAttractMovieAudioMode == 1) {
            if (gAttractMovieAudioPendingSourceAddr != 0) {
                gAttractMovieAudioMixSourceAddr = gAttractMovieAudioPendingSourceAddr;
            }
            gAttractMovieAudioPrevDmaCallback();
            gAttractMovieAudioPendingSourceAddr = AIGetDMAStartAddr() + 0x80000000 /* phys -> cached RAM */;
        } else {
            gAttractMovieAudioPrevDmaCallback();
            gAttractMovieAudioMixSourceAddr = AIGetDMAStartAddr() + 0x80000000 /* phys -> cached RAM */;
        }

        gAttractMovieAudioDmaBufferIndex ^= 1u;
        AIInitDMA((u32)(gAttractMovieAudioDmaBuffer +
                        (gAttractMovieAudioDmaBufferIndex * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE)),
                  ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        interrupts = OSEnableInterrupts();
        if (gAttractMovieAudioMixSourceAddr != 0) {
            DCInvalidateRange((void*)gAttractMovieAudioMixSourceAddr, ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        }
        AttractMovieAudio_Mix((s16*)(gAttractMovieAudioDmaBuffer +
                                     (gAttractMovieAudioDmaBufferIndex * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE)),
                              (s16*)gAttractMovieAudioMixSourceAddr, ATTRACT_MOVIE_AUDIO_DMA_SAMPLE_COUNT);
        DCFlushRange(gAttractMovieAudioDmaBuffer +
                         (gAttractMovieAudioDmaBufferIndex * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE),
                     ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        OSRestoreInterrupts(interrupts);
    }
}

static void AttractMovieAudio_Mix(s16* destination, s16* source, u32 sampleCount) {
    u16 volumeScale;
    u32 validSamples;
    u32 process;
    int mixed;
    s16* audioPtr;
    u32 remain;
    u32 cnt;
    s16* dst;
    s16* src;

    if (source != NULL) {
        if ((gAttractMoviePlayer.isOpen != 0) && (gAttractMoviePlayer.internalState == 2) &&
            (gAttractMoviePlayer.audioExists != 0)) {
            cnt = sampleCount;
            dst = destination;
            src = source;
            for (;;) {
                do {
                    if (gAttractMoviePlayer.curAudioBuffer == NULL) {
                        gAttractMoviePlayer.curAudioBuffer = (AttractMovieAudioBuffer*)PopDecodedAudioBuffer(0);
                        if (gAttractMoviePlayer.curAudioBuffer == NULL) {
                            memcpy(dst, src, cnt << 2);
                            return;
                        }
                        gAttractMoviePlayer.curAudioFrameNumber = gAttractMoviePlayer.curAudioBuffer->frameNumber;
                    }
                    validSamples = gAttractMoviePlayer.curAudioBuffer->validSample;
                } while (validSamples == 0);
                if (validSamples >= cnt) {
                    process = cnt;
                } else {
                    process = validSamples;
                }
                audioPtr = gAttractMoviePlayer.curAudioBuffer->curPtr;
                for (remain = 0; remain < process; remain = remain + 1) {
                    if (gAttractMoviePlayer.rampCount != 0) {
                        gAttractMoviePlayer.rampCount += -1;
                        gAttractMoviePlayer.curVolume += gAttractMoviePlayer.deltaVolume;
                    } else {
                        gAttractMoviePlayer.curVolume = gAttractMoviePlayer.targetVolume;
                    }
                    volumeScale = gAttractMovieVolumeScale[(int)gAttractMoviePlayer.curVolume];
                    mixed = (int)*src + ((int)((u32)volumeScale * (int)*audioPtr) >> 0xf);
                    if (mixed < S16_MIN) {
                        mixed = S16_MIN;
                    }
                    if (S16_MAX < mixed) {
                        mixed = S16_MAX;
                    }
                    *dst = mixed;
                    mixed = src[1] + ((int)((u32)volumeScale * audioPtr[1]) >> 0xf);
                    if (mixed < S16_MIN) {
                        mixed = S16_MIN;
                    }
                    if (S16_MAX < mixed) {
                        mixed = S16_MAX;
                    }
                    dst[1] = mixed;
                    dst += 2;
                    src += 2;
                    audioPtr += 2;
                }
                cnt -= process;
                gAttractMoviePlayer.curAudioBuffer->validSample =
                    gAttractMoviePlayer.curAudioBuffer->validSample - process;
                gAttractMoviePlayer.curAudioBuffer->curPtr = audioPtr;
                if (gAttractMoviePlayer.curAudioBuffer->validSample == 0) {
                    PushFreeAudioBuffer(gAttractMoviePlayer.curAudioBuffer);
                    gAttractMoviePlayer.curAudioBuffer = NULL;
                }
                if (cnt == 0) {
                    break;
                }
            }
        } else {
            memcpy(destination, source, sampleCount << 2);
        }
    } else if ((gAttractMoviePlayer.isOpen != 0) && (gAttractMoviePlayer.internalState == 2) &&
               (gAttractMoviePlayer.audioExists != 0)) {
        cnt = sampleCount;
        dst = destination;
        for (;;) {
            do {
                if (gAttractMoviePlayer.curAudioBuffer == NULL) {
                    gAttractMoviePlayer.curAudioBuffer = (AttractMovieAudioBuffer*)PopDecodedAudioBuffer(0);
                    if (gAttractMoviePlayer.curAudioBuffer == NULL) {
                        memset(dst, 0, cnt << 2);
                        return;
                    }
                    gAttractMoviePlayer.curAudioFrameNumber = gAttractMoviePlayer.curAudioBuffer->frameNumber;
                }
                validSamples = gAttractMoviePlayer.curAudioBuffer->validSample;
            } while (validSamples == 0);
            if (validSamples >= cnt) {
                validSamples = cnt;
            }
            audioPtr = gAttractMoviePlayer.curAudioBuffer->curPtr;
            for (remain = 0; remain < validSamples; remain = remain + 1) {
                if (gAttractMoviePlayer.rampCount != 0) {
                    gAttractMoviePlayer.rampCount += -1;
                    gAttractMoviePlayer.curVolume += gAttractMoviePlayer.deltaVolume;
                } else {
                    gAttractMoviePlayer.curVolume = gAttractMoviePlayer.targetVolume;
                }
                volumeScale = gAttractMovieVolumeScale[(int)gAttractMoviePlayer.curVolume];
                mixed = (int)((u32)volumeScale * (int)*audioPtr) >> 0xf;
                if (mixed < S16_MIN) {
                    mixed = S16_MIN;
                }
                if (S16_MAX < mixed) {
                    mixed = S16_MAX;
                }
                *dst = mixed;
                mixed = (int)((u32)volumeScale * audioPtr[1]) >> 0xf;
                if (mixed < S16_MIN) {
                    mixed = S16_MIN;
                }
                if (S16_MAX < mixed) {
                    mixed = S16_MAX;
                }
                dst[1] = mixed;
                dst += 2;
                audioPtr += 2;
            }
            cnt -= validSamples;
            gAttractMoviePlayer.curAudioBuffer->validSample =
                gAttractMoviePlayer.curAudioBuffer->validSample - validSamples;
            gAttractMoviePlayer.curAudioBuffer->curPtr = audioPtr;
            if (gAttractMoviePlayer.curAudioBuffer->validSample == 0) {
                PushFreeAudioBuffer(gAttractMoviePlayer.curAudioBuffer);
                gAttractMoviePlayer.curAudioBuffer = NULL;
            }
            if (cnt == 0) {
                break;
            }
        }
    } else {
        memset(destination, 0, sampleCount << 2);
    }
}

BOOL Movie_SetVolumeFade(int volume, int fadeFrames) {
    BOOL interrupts;
    f32 targetVolume;
    int rampCount;

    if ((gAttractMoviePlayer.isOpen != 0) && (gAttractMoviePlayer.audioExists != 0)) {
        if (volume > MOVIE_VOLUME_MAX) {
            volume = MOVIE_VOLUME_MAX;
        }
        if (volume < 0) {
            volume = 0;
        }
        if (fadeFrames > MOVIE_FADE_FRAMES_MAX) {
            fadeFrames = MOVIE_FADE_FRAMES_MAX;
        }
        if (fadeFrames < 0) {
            fadeFrames = 0;
        }

        interrupts = OSDisableInterrupts();
        targetVolume = volume;
        gAttractMoviePlayer.targetVolume = targetVolume;
        if (fadeFrames != 0) {
            rampCount = fadeFrames << 5;
            gAttractMoviePlayer.rampCount = rampCount;
            gAttractMoviePlayer.deltaVolume = (targetVolume - gAttractMoviePlayer.curVolume) / rampCount;
        } else {
            gAttractMoviePlayer.rampCount = 0;
            gAttractMoviePlayer.curVolume = targetVolume;
        }
        OSRestoreInterrupts(interrupts);
        return TRUE;
    }
    return FALSE;
}

void THPPlayerDrawCurrentFrame(void* yBuf, void* uBuf, void* vBuf, u32 width, u32 height) {
    int halfHeight;
    int halfWidth;
    GXTexObj yTexObj;
    GXTexObj uTexObj;
    GXTexObj vTexObj;

    gxSetZMode_(1, GX_LEQUAL, 1);
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_CLEAR);
    GXSetColorUpdate(GX_TRUE);
    GXSetAlphaUpdate(GX_FALSE);
    GXSetCullMode(GX_CULL_BACK);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetNumTexGens(2);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetNumTevStages(4);
    GXSetNumIndStages(0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_A0);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP2, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_2, GX_FALSE, GX_TEVPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_APREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K1);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K1_A);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ONE, GX_CC_CPREV);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_TEXA, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE3);
    GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_APREV, GX_CC_CPREV, GX_CC_KONST, GX_CC_ZERO);
    GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevKColorSel(GX_TEVSTAGE3, GX_TEV_KCSEL_K2);
    GXSetTevColorS10(GX_TEVREG0, sMovieTevColor0);
    GXSetTevKColor(GX_KCOLOR0, sMovieKColor0);
    GXSetTevKColor(GX_KCOLOR1, sMovieKColor1);
    GXSetTevKColor(GX_KCOLOR2, sMovieKColor2);
    GXSetTevSwapModeTable(GX_TEV_SWAP0, GX_CH_RED, GX_CH_GREEN, GX_CH_BLUE, GX_CH_ALPHA);
    GXInitTexObj(&yTexObj, yBuf, width, height, GX_TF_I8, GX_CLAMP, GX_CLAMP, GX_FALSE);
    GXInitTexObjLOD(&yTexObj, GX_NEAR, GX_NEAR, 0.0f, 0.0f, 0.0f, GX_FALSE, GX_FALSE, GX_ANISO_1);
    GXLoadTexObj(&yTexObj, GX_TEXMAP0);
    GXInitTexObj(&uTexObj, uBuf, halfWidth = (short)width >> 1, halfHeight = (short)height >> 1, GX_TF_I8, GX_CLAMP,
                 GX_CLAMP, GX_FALSE);
    GXInitTexObjLOD(&uTexObj, GX_NEAR, GX_NEAR, 0.0f, 0.0f, 0.0f, GX_FALSE, GX_FALSE, GX_ANISO_1);
    GXLoadTexObj(&uTexObj, GX_TEXMAP1);
    GXInitTexObj(&vTexObj, vBuf, halfWidth, halfHeight, GX_TF_I8, GX_CLAMP, GX_CLAMP, GX_FALSE);
    GXInitTexObjLOD(&vTexObj, GX_NEAR, GX_NEAR, 0.0f, 0.0f, 0.0f, GX_FALSE, GX_FALSE, GX_ANISO_1);
    GXLoadTexObj(&vTexObj, GX_TEXMAP2);
}
