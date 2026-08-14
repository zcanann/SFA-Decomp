/*
 * dll_3e - THP attract-mode movie playback (FRONT/attract_movie).
 *
 * Drives the streamed THP attract movie via the VI post-retrace callback:
 * PlayControl() runs each retrace, pops a decoded texture set from the
 * decode pipeline, paces it against the audio track (single-field /
 * even-field / odd-field cadence from playFlags), recycles the previously
 * displayed set back to its message queue, and detects end-of-movie /
 * loop completion.
 *
 * THPPlayerPlay/THPPlayerStop arm and tear down the player (state machine
 * in AttractMoviePlayer.state / internalState, with worker threads for
 * video decode, audio decode and DVD read).
 *
 * prepareAttractMode() seeks to a movie within the attract package
 * (offset table indexed by movieIndex), spins up the decode/read threads,
 * primes the message queues (InitAllMessageQueue) and installs the
 * retrace callback. Operates on the AttractMovieControl block at
 * gAttractMovieAudioDmaBuffer and the AttractMoviePlayer at gAttractMoviePlayer.
 */
#include "global.h"
#include "dolphin/ai.h"
#include "dolphin/os.h"
#include "dolphin/vi/vifuncs.h"
#include "main/dll/FRONT/dll_3B.h"
#include "main/dll/FRONT/n_options.h"
#include "main/attract_movie_api.h"
#include "main/fileio.h"
#include "main/audio_decode_thread.h"
#include "main/dll/FRONT/picmenu.h"
#include "main/dll/dll_3e_api.h"
#include "dolphin/thp/THPDraw.h"

typedef struct AttractMovieControl {
    u8 pad000[0x560];
    u32 readBufBegin; /* 0x560 */
    u32 readBufEnd;   /* 0x564 */
    u8 pad568[0x5f0 - 0x568];
    u32 movieCount;     /* 0x5f0 */
    u32 firstMovieSize; /* 0x5f4 */
    s32 initReadSize;   /* 0x5f8 */
    u8 pad5fc[0x600 - 0x5fc];
    u32 offsetTable; /* 0x600 */
    u32 dataOffset;  /* 0x604 */
    u8 pad608[0x638 - 0x608];
    s32 enabled;    /* 0x638 */
    u8 isPrepared;  /* 0x63c */
    u8 field63d;    /* 0x63d */
    u8 playFlags;   /* 0x63e */
    u8 audioExists; /* 0x63f */
    u8 pad640[0x648 - 0x640];
    s32 preloaded;   /* 0x648 */
    void* loopFrame; /* 0x64c */
    u32 frameOffset; /* 0x650 */
    u32 frameSize;   /* 0x654 */
    u32 movieIndex;  /* 0x658 */
    u8 pad65c[0x670 - 0x65c];
    u32 field670; /* 0x670 */
    u8 pad674[0x684 - 0x674];
    u32 field684; /* 0x684 */
    u32 field688; /* 0x688 */
    u32 field68c; /* 0x68c */
    u32 field690; /* 0x690 */
} AttractMovieControl;

STATIC_ASSERT(offsetof(AttractMovieControl, readBufBegin) == 0x560);
STATIC_ASSERT(offsetof(AttractMovieControl, movieCount) == 0x5f0);
STATIC_ASSERT(offsetof(AttractMovieControl, offsetTable) == 0x600);
STATIC_ASSERT(offsetof(AttractMovieControl, enabled) == 0x638);
STATIC_ASSERT(offsetof(AttractMovieControl, isPrepared) == 0x63c);
STATIC_ASSERT(offsetof(AttractMovieControl, preloaded) == 0x648);
STATIC_ASSERT(offsetof(AttractMovieControl, frameOffset) == 0x650);
STATIC_ASSERT(offsetof(AttractMovieControl, field670) == 0x670);
STATIC_ASSERT(offsetof(AttractMovieControl, field684) == 0x684);
STATIC_ASSERT(offsetof(AttractMovieControl, field690) == 0x690);

/* playFlags bits (shared by AttractMoviePlayer and AttractMovieControl) */
enum {
    THP_PLAY_LOOP = 1,
    THP_PLAY_EVEN_FIELD = 2,
    THP_PLAY_ODD_FIELD = 4
};

extern OSMessageQueue gAttractMoviePrepareReadyQueue;
static void InitAllMessageQueue(void);

u8 gAttractMovieLoopCompleted;
OSMessage lbl_803DD67C;
u32 gAttractMovieAudioDmaBufferIndex;
u32 gAttractMovieAudioPendingSourceAddr;
u32 gAttractMovieAudioMixSourceAddr;
s32 gAttractMovieAudioMode;
AIDCallback gAttractMovieAudioPrevDmaCallback;
static VIRetraceCallback OldVIPostCallback;

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
        if ((void*)gAttractMoviePlayer.curAudioNumber != NULL) {
            OSSendMessage(&gAttractMovieSpentTextureSetQueue, (OSMessage)gAttractMoviePlayer.curAudioNumber,
                          OS_MESSAGE_NOBLOCK);
        }
        gAttractMoviePlayer.curAudioNumber = (s32)decodedTexture;
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

BOOL prepareAttractMode(u32 movieIndex, s32 playFlags) {
    char* base;
    AttractMovieControl* ctrl;
    s32 readyMsg;
    s32 startOffset;

    base = gAttractMovieAudioDmaBuffer;
    ctrl = (AttractMovieControl*)base;
    gAttractMovieLoopCompleted = 0;

    if (ctrl->enabled != 0 && ctrl->isPrepared == 0) {
        if ((s32)movieIndex > 0) {
            u32 offsetTable = ctrl->offsetTable;

            if (offsetTable == 0) {
                return FALSE;
            }
            if (ctrl->movieCount > movieIndex) {
                if (DVDRead((DVDFileInfo*)(base + 0x5a0), base + 0x560, 0x20,
                            offsetTable + ((movieIndex - 1) * sizeof(u32))) < 0) {
                    return FALSE;
                }

                ctrl->frameOffset = ctrl->dataOffset + ctrl->readBufBegin;
                ctrl->movieIndex = movieIndex;
                ctrl->frameSize = ctrl->readBufEnd - ctrl->readBufBegin;
            } else {
                return FALSE;
            }
        } else {
            ctrl->frameOffset = ctrl->dataOffset;
            ctrl->frameSize = ctrl->firstMovieSize;
            ctrl->movieIndex = movieIndex;
        }

        ctrl->playFlags = playFlags;
        ctrl->field670 = 0;

        if (ctrl->preloaded != 0) {
            if (DVDRead((DVDFileInfo*)(base + 0x5a0), ctrl->loopFrame, ctrl->initReadSize, ctrl->dataOffset) < 0) {
                return FALSE;
            }
            startOffset = ((s32)ctrl->loopFrame + ctrl->frameOffset) - ctrl->dataOffset;
            CreateVideoDecodeThread(0xf, startOffset);
            if (ctrl->audioExists != 0) {
                CreateAudioDecodeThread(0xc, (void*)startOffset);
            }
        } else {
            CreateVideoDecodeThread(0xf, 0);
            if (ctrl->audioExists != 0) {
                CreateAudioDecodeThread(0xc, NULL);
            }
            CreateReadThread(8);
        }

        InitAllMessageQueue();
        VideoDecodeThreadStart();
        if (ctrl->audioExists != 0) {
            AudioDecodeThreadStart();
        }
        if (ctrl->preloaded == 0) {
            ReadThreadStart();
        }

        OSReceiveMessage((OSMessageQueue*)(base + 0x52c), (OSMessage*)&readyMsg, OS_MESSAGE_BLOCK);
        if (readyMsg == 0) {
            return FALSE;
        }
        ctrl->isPrepared = 1;
        ctrl->field63d = 0;
        ctrl->field68c = 0;
        ctrl->field690 = 0;
        ctrl->field684 = 0;
        ctrl->field688 = 0;
        OldVIPostCallback = VISetPostRetraceCallback(PlayControl);
        return TRUE;
    }
    return FALSE;
}

void PrepareReady(void* msg) {
    OSSendMessage(&gAttractMoviePrepareReadyQueue, msg, OS_MESSAGE_BLOCK);
}

static void InitAllMessageQueue(void) {
    AttractMoviePlayer* player;
    s32 i;

    player = &gAttractMoviePlayer;
    if (player->isOnMemory == 0) {
        for (i = 0; i < 10; i++) {
            PushFreeReadBuffer((OSMessage)&player->readBuffer[i]);
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

    OSInitMessageQueue(&gAttractMoviePrepareReadyQueue, &lbl_803DD67C, 1);
}
