/*
 * THP attract-movie playback back end (AttractMoviePlayer gAttractMoviePlayer,
 * attract_movie.h). Three jobs:
 *
 *  - Video: THPPlayerDrawCurrentFrame builds the GX TEV pipeline that
 *    converts the decoded Y/U/V planes into RGB and blits the current
 *    frame; AttractMovie_DrawTextureCallback / AttractMovie_AddVideoTevStages are the
 *    per-model render hooks, THPPlayerPostDrawDone recycles spent
 *    texture sets, THPPlayerGetVideoInfo exposes the frame dimensions.
 *  - Audio: AttractMovieAudio_Mix scales decoded PCM by a fading volume
 *    and mixes (or copies/clears) it into the AI output, draining decoded
 *    buffers from dll_3b's queue (PopDecodedAudioBuffer). Movie_SetVolumeFade
 *    arms the volume ramp; AttractMovieAudio_DmaCallback double-buffers the
 *    AI DMA and re-mixes each completed buffer.
 *  - Timing: ProperTimingForGettingNextFrame decides, from the field/retrace
 *    counters and the THP frame rate, when the next video frame is due.
 */
#include "dolphin/ai.h"
#include "dolphin/os.h"
#include "dolphin/vi.h"
#include "main/model.h"
#include "main/dll/FRONT/dll_3B.h"
#include "dolphin/gx/GXTexture.h"
#include "main/dll/FRONT/picmenu.h"
#include "main/dll/FRONT/n_options.h"
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

static const GXColorS10 sMovieTevColor0 = {-90, 0, -114, 135};
static const GXColor sMovieKColor0 = {0x00, 0x00, 0xE2, 0x58};
static const GXColor sMovieKColor1 = {0xB3, 0x00, 0x00, 0xB6};
static const GXColor sMovieKColor2 = {0xFF, 0x00, 0xFF, 0x80};

#define MOVIE_VOLUME_MAX      0x7f
#define MOVIE_FADE_FRAMES_MAX 60000
#define S16_MIN               (-0x8000)
#define S16_MAX               0x7fff

s32 gAttractMovieAudioActive;

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
char gAttractMovieAudioDmaBuffer[ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES + 3 * sizeof(OSMessage)];

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
                        gAttractMoviePlayer.rampCount = gAttractMoviePlayer.rampCount + -1;
                        gAttractMoviePlayer.curVolume = gAttractMoviePlayer.curVolume + gAttractMoviePlayer.deltaVolume;
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
                    dst = dst + 2;
                    src = src + 2;
                    audioPtr = audioPtr + 2;
                }
                cnt = cnt - process;
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
                    gAttractMoviePlayer.rampCount = gAttractMoviePlayer.rampCount + -1;
                    gAttractMoviePlayer.curVolume = gAttractMoviePlayer.curVolume + gAttractMoviePlayer.deltaVolume;
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
                dst = dst + 2;
                audioPtr = audioPtr + 2;
            }
            cnt = cnt - validSamples;
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

BOOL THPPlayerGetVideoInfo(void* dst) {
    if (gAttractMoviePlayer.isOpen != 0) {
        memcpy(dst, &gAttractMoviePlayer.videoInfo, sizeof(gAttractMoviePlayer.videoInfo));
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

/* .bss glue 0x803A5CCC-0x803A5F08 */
AttractMoviePlayer gAttractMoviePlayer;
char gPicMenuDvdReadBuffer[0x40];
u8 gAttractMoviePrepareReadyQueue[0x34];
OSMessageQueue gAttractMovieSpentTextureSetQueue;
