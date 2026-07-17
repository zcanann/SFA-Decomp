/*
 * THP attract-movie playback back end (AttractMoviePlayer lbl_803A5D60,
 * attract_movie.h). Three jobs:
 *
 *  - Video: THPPlayerDrawCurrentFrame builds the GX TEV pipeline that
 *    converts the decoded Y/U/V planes into RGB and blits the current
 *    frame; AttractMovie_DrawTextureCallback / fn_80118240 are the
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
#include "track/intersect_depth_state_api.h"
#include "dolphin/os.h"
#include "dolphin/vi.h"
#include "main/dll/FRONT/attract_movie.h"
#include "main/attract_movie_api.h"
#include "main/model.h"
#include "string.h"
#include "main/dll/FRONT/dll_3B.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXBump.h"
#include "main/dll/FRONT/picmenu.h"

typedef struct
{
    u32 a;
    u32 b;
} TevColorS10Pair;

#define MOVIE_VOLUME_MAX      0x7f
#define MOVIE_FADE_FRAMES_MAX 60000
#define S16_MIN               (-0x8000)
#define S16_MAX               0x7fff

extern TevColorS10Pair lbl_803E1D30; /* TEV color-S10 / k-color constants */
extern u32 lbl_803E1D38;
extern u32 lbl_803E1D3C;
extern u32 lbl_803E1D40;
extern s32 lbl_803DD660;               /* texture-set free queue active */
extern AIDCallback lbl_803DD668;       /* AI DMA done callback */
extern s32 lbl_803DD66C;               /* DMA callback phase */
extern u32 lbl_803DD670;               /* previous/pending DMA source addr */
extern u32 lbl_803DD674;               /* queued next DMA source addr */
extern u32 lbl_803DD678;               /* AI DMA double-buffer index */
extern f32 lbl_803E1D50;               /* playback time accumulator */
extern OSMessageQueue lbl_803A5CCC[1]; /* spent texture-set queue */

extern void GXSetTexCoordGen2(GXTexCoordID dst_coord, GXTexGenType func, GXTexGenSrc src_param, u32 mtx,
                              GXBool normalize, u32 pt_texmtx);
extern void GXSetNumTexGens(u8 nTexGens);
extern void GXSetTevColorIn(GXTevStageID stage, GXTevColorArg a, GXTevColorArg b, GXTevColorArg c, GXTevColorArg d);
extern void GXSetTevAlphaIn(GXTevStageID stage, GXTevAlphaArg a, GXTevAlphaArg b, GXTevAlphaArg c, GXTevAlphaArg d);
extern void GXSetTevColorOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp,
                            GXTevRegID out_reg);
extern void GXSetTevAlphaOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp,
                            GXTevRegID out_reg);
extern u32 GXSetTevColorS10();
extern u32 GXSetTevKColor();
extern void GXSetTevKColorSel(GXTevStageID stage, GXTevKColorSel sel);
extern void GXSetTevKAlphaSel(GXTevStageID stage, GXTevKAlphaSel sel);
extern void GXSetTevSwapMode(GXTevStageID stage, GXTevSwapSel ras_sel, GXTevSwapSel tex_sel);
extern void GXSetTevSwapModeTable(GXTevSwapSel table, GXTevColorChan red, GXTevColorChan green, GXTevColorChan blue,
                                  GXTevColorChan alpha);
extern void GXSetAlphaCompare(GXCompare comp0, u8 ref0, GXAlphaOp op, GXCompare comp1, u8 ref1);
extern void GXSetTevOrder(GXTevStageID stage, GXTexCoordID coord, GXTexMapID map, GXChannelID color);
extern void GXSetNumTevStages(u8 nStages);
extern void fn_8004C7AC(void* yTexture, void* uTexture, void* vTexture, int width, int height);

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
char lbl_803A57C0[0x50C]; /* AI DMA double buffer */

void THPPlayerDrawCurrentFrame(void* yBuf, void* uBuf, void* vBuf, u32 width, u32 height)
{
    int halfHeight;
    int halfWidth;
    u32 kColor0;
    u32 kColor1;
    u32 kColor2;
    TevColorS10Pair tevColorS10;
    GXTexObj yTexObj;
    GXTexObj uTexObj;
    GXTexObj vTexObj;

    gxSetZMode_(1, 3, 1);
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
    tevColorS10 = lbl_803E1D30;
    GXSetTevColorS10(GX_TEVREG0, &tevColorS10);
    kColor0 = lbl_803E1D38;
    GXSetTevKColor(GX_KCOLOR0, &kColor0);
    kColor1 = lbl_803E1D3C;
    GXSetTevKColor(GX_KCOLOR1, &kColor1);
    kColor2 = lbl_803E1D40;
    GXSetTevKColor(GX_KCOLOR2, &kColor2);
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

BOOL Movie_SetVolumeFade(int volume, int fadeFrames)
{
    BOOL interrupts;
    f32 targetVolume;
    int rampCount;

    if ((lbl_803A5D60.isOpen != 0) && (lbl_803A5D60.audioExists != 0))
    {
        if (volume > MOVIE_VOLUME_MAX)
        {
            volume = MOVIE_VOLUME_MAX;
        }
        if (volume < 0)
        {
            volume = 0;
        }
        if (fadeFrames > MOVIE_FADE_FRAMES_MAX)
        {
            fadeFrames = MOVIE_FADE_FRAMES_MAX;
        }
        if (fadeFrames < 0)
        {
            fadeFrames = 0;
        }

        interrupts = OSDisableInterrupts();
        targetVolume = volume;
        lbl_803A5D60.targetVolume = targetVolume;
        if (fadeFrames != 0)
        {
            rampCount = fadeFrames << 5;
            lbl_803A5D60.rampCount = rampCount;
            lbl_803A5D60.deltaVolume = (targetVolume - lbl_803A5D60.curVolume) / rampCount;
        }
        else
        {
            lbl_803A5D60.rampCount = 0;
            lbl_803A5D60.curVolume = targetVolume;
        }
        OSRestoreInterrupts(interrupts);
        return TRUE;
    }
    return FALSE;
}

void AttractMovieAudio_Mix(s16* destination, s16* source, u32 sampleCount)
{
    u16 volumeScale;
    u32 validSamples;
    u32 process;
    int mixed;
    s16* audioPtr;
    u32 remain;
    u32 cnt;
    s16* dst;
    s16* src;

    if (source != NULL)
    {
        if ((lbl_803A5D60.isOpen != 0) && (lbl_803A5D60.internalState == 2) && (lbl_803A5D60.audioExists != 0))
        {
            cnt = sampleCount;
            dst = destination;
            src = source;
            for (;;)
            {
                do
                {
                    if (lbl_803A5D60.curAudioBuffer == NULL)
                    {
                        lbl_803A5D60.curAudioBuffer = (AttractMovieAudioBuffer*)PopDecodedAudioBuffer(0);
                        if (lbl_803A5D60.curAudioBuffer == NULL)
                        {
                            memcpy(dst, src, cnt << 2);
                            return;
                        }
                        lbl_803A5D60.curAudioFrameNumber = lbl_803A5D60.curAudioBuffer->frameNumber;
                    }
                    validSamples = lbl_803A5D60.curAudioBuffer->validSample;
                } while (validSamples == 0);
                if (validSamples >= cnt)
                {
                    process = cnt;
                }
                else
                {
                    process = validSamples;
                }
                audioPtr = lbl_803A5D60.curAudioBuffer->curPtr;
                for (remain = 0; remain < process; remain = remain + 1)
                {
                    if (lbl_803A5D60.rampCount != 0)
                    {
                        lbl_803A5D60.rampCount = lbl_803A5D60.rampCount + -1;
                        lbl_803A5D60.curVolume = lbl_803A5D60.curVolume + lbl_803A5D60.deltaVolume;
                    }
                    else
                    {
                        lbl_803A5D60.curVolume = lbl_803A5D60.targetVolume;
                    }
                    volumeScale = gAttractMovieVolumeScale[(int)lbl_803A5D60.curVolume];
                    mixed = (int)*src + ((int)((u32)volumeScale * (int)*audioPtr) >> 0xf);
                    if (mixed < S16_MIN)
                    {
                        mixed = S16_MIN;
                    }
                    if (S16_MAX < mixed)
                    {
                        mixed = S16_MAX;
                    }
                    *dst = mixed;
                    mixed = src[1] + ((int)((u32)volumeScale * audioPtr[1]) >> 0xf);
                    if (mixed < S16_MIN)
                    {
                        mixed = S16_MIN;
                    }
                    if (S16_MAX < mixed)
                    {
                        mixed = S16_MAX;
                    }
                    dst[1] = mixed;
                    dst = dst + 2;
                    src = src + 2;
                    audioPtr = audioPtr + 2;
                }
                cnt = cnt - process;
                lbl_803A5D60.curAudioBuffer->validSample = lbl_803A5D60.curAudioBuffer->validSample - process;
                lbl_803A5D60.curAudioBuffer->curPtr = audioPtr;
                if (lbl_803A5D60.curAudioBuffer->validSample == 0)
                {
                    PushFreeAudioBuffer(lbl_803A5D60.curAudioBuffer);
                    lbl_803A5D60.curAudioBuffer = NULL;
                }
                if (cnt == 0)
                {
                    break;
                }
            }
        }
        else
        {
            memcpy(destination, source, sampleCount << 2);
        }
    }
    else if ((lbl_803A5D60.isOpen != 0) && (lbl_803A5D60.internalState == 2) && (lbl_803A5D60.audioExists != 0))
    {
        cnt = sampleCount;
        dst = destination;
        for (;;)
        {
            do
            {
                if (lbl_803A5D60.curAudioBuffer == NULL)
                {
                    lbl_803A5D60.curAudioBuffer = (AttractMovieAudioBuffer*)PopDecodedAudioBuffer(0);
                    if (lbl_803A5D60.curAudioBuffer == NULL)
                    {
                        memset(dst, 0, cnt << 2);
                        return;
                    }
                    lbl_803A5D60.curAudioFrameNumber = lbl_803A5D60.curAudioBuffer->frameNumber;
                }
                validSamples = lbl_803A5D60.curAudioBuffer->validSample;
            } while (validSamples == 0);
            if (validSamples >= cnt)
            {
                validSamples = cnt;
            }
            audioPtr = lbl_803A5D60.curAudioBuffer->curPtr;
            for (remain = 0; remain < validSamples; remain = remain + 1)
            {
                if (lbl_803A5D60.rampCount != 0)
                {
                    lbl_803A5D60.rampCount = lbl_803A5D60.rampCount + -1;
                    lbl_803A5D60.curVolume = lbl_803A5D60.curVolume + lbl_803A5D60.deltaVolume;
                }
                else
                {
                    lbl_803A5D60.curVolume = lbl_803A5D60.targetVolume;
                }
                volumeScale = gAttractMovieVolumeScale[(int)lbl_803A5D60.curVolume];
                mixed = (int)((u32)volumeScale * (int)*audioPtr) >> 0xf;
                if (mixed < S16_MIN)
                {
                    mixed = S16_MIN;
                }
                if (S16_MAX < mixed)
                {
                    mixed = S16_MAX;
                }
                *dst = mixed;
                mixed = (int)((u32)volumeScale * audioPtr[1]) >> 0xf;
                if (mixed < S16_MIN)
                {
                    mixed = S16_MIN;
                }
                if (S16_MAX < mixed)
                {
                    mixed = S16_MAX;
                }
                dst[1] = mixed;
                dst = dst + 2;
                audioPtr = audioPtr + 2;
            }
            cnt = cnt - validSamples;
            lbl_803A5D60.curAudioBuffer->validSample = lbl_803A5D60.curAudioBuffer->validSample - validSamples;
            lbl_803A5D60.curAudioBuffer->curPtr = audioPtr;
            if (lbl_803A5D60.curAudioBuffer->validSample == 0)
            {
                PushFreeAudioBuffer(lbl_803A5D60.curAudioBuffer);
                lbl_803A5D60.curAudioBuffer = NULL;
            }
            if (cnt == 0)
            {
                break;
            }
        }
    }
    else
    {
        memset(destination, 0, sampleCount << 2);
    }
}

void AttractMovieAudio_DmaCallback(void)
{
    BOOL interrupts;

    if (lbl_803DD66C == 0)
    {
        lbl_803DD678 ^= 1;
        AIInitDMA((u32)(lbl_803A57C0 + (lbl_803DD678 * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE)),
                  ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        interrupts = OSEnableInterrupts();
        AttractMovieAudio_Mix((s16*)(lbl_803A57C0 + (lbl_803DD678 * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE)), NULL,
                              ATTRACT_MOVIE_AUDIO_DMA_SAMPLE_COUNT);
        DCFlushRange(lbl_803A57C0 + (lbl_803DD678 * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE),
                     ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        OSRestoreInterrupts(interrupts);
    }
    else
    {
        if (lbl_803DD66C == 1)
        {
            if (lbl_803DD674 != 0)
            {
                lbl_803DD670 = lbl_803DD674;
            }
            lbl_803DD668();
            lbl_803DD674 = AIGetDMAStartAddr() + 0x80000000 /* phys -> cached RAM */;
        }
        else
        {
            lbl_803DD668();
            lbl_803DD670 = AIGetDMAStartAddr() + 0x80000000 /* phys -> cached RAM */;
        }

        lbl_803DD678 ^= 1;
        AIInitDMA((u32)(lbl_803A57C0 + (lbl_803DD678 * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE)),
                  ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        interrupts = OSEnableInterrupts();
        if (lbl_803DD670 != 0)
        {
            DCInvalidateRange((void*)lbl_803DD670, ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        }
        AttractMovieAudio_Mix((s16*)(lbl_803A57C0 + (lbl_803DD678 * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE)),
                              (s16*)lbl_803DD670, ATTRACT_MOVIE_AUDIO_DMA_SAMPLE_COUNT);
        DCFlushRange(lbl_803A57C0 + (lbl_803DD678 * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE),
                     ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE);
        OSRestoreInterrupts(interrupts);
    }
}

void THPPlayerPostDrawDone(void)
{
    OSMessage msg;
    OSMessage textureSet;

    if (lbl_803DD660 != 0)
    {
        while (TRUE)
        {
            if (OSReceiveMessage(lbl_803A5CCC, &msg, OS_MESSAGE_NOBLOCK) == TRUE)
            {
                textureSet = msg;
            }
            else
            {
                textureSet = NULL;
            }
            if (textureSet == NULL)
            {
                break;
            }
            PushFreeTextureSet(textureSet);
        }
    }
}

BOOL THPPlayerGetVideoInfo(void* dst)
{
    if (lbl_803A5D60.isOpen != 0)
    {
        memcpy(dst, &lbl_803A5D60.videoInfo, sizeof(lbl_803A5D60.videoInfo));
        return TRUE;
    }
    return FALSE;
}

void fn_80118240(void)
{
    AttractMovieTextureSet* textureSet;

    if (gAttractMovieState == 2)
    {
        textureSet = lbl_803A5D60.curTextureSet;
        fn_8004C7AC(textureSet->yTexture, textureSet->uTexture, textureSet->vTexture, (s16)lbl_803A5D60.videoInfo.xSize,
                    (s16)lbl_803A5D60.videoInfo.ySize);
    }
}

BOOL AttractMovie_DrawTextureCallback(int unused, u32* modelPtr, u32 renderOpIdx)
{
    AttractMovieTextureSet* textureSet;
    u8* renderOp;

    if (modelPtr != NULL)
    {
        renderOp = (u8*)ObjModel_GetRenderOp((ModelFileHeader*)*modelPtr, renderOpIdx);
    }
    else
    {
        renderOp = NULL;
    }

    if (((renderOp == NULL) || (renderOp[0x29] == 1)) && (gAttractMovieState == 2))
    {
        textureSet = lbl_803A5D60.curTextureSet;
        THPPlayerDrawCurrentFrame(textureSet->yTexture, textureSet->uTexture, textureSet->vTexture,
                                  (s16)lbl_803A5D60.videoInfo.xSize, (s16)lbl_803A5D60.videoInfo.ySize);
        return TRUE;
    }
    return FALSE;
}

int ProperTimingForGettingNextFrame(void)
{
    int frame;
    s64 tick;

    if ((lbl_803A5D60.playFlags & 2) != 0)
    {
        if (VIGetNextField() != 0)
        {
            goto returnFalse;
        }
        return TRUE;
    }

    if ((lbl_803A5D60.playFlags & 4) != 0)
    {
        if (VIGetNextField() != 1)
        {
            goto returnFalse;
        }
        return TRUE;
    }

    frame = (int)(lbl_803E1D50 * lbl_803A5D60.header.mFrameRate);
    if (VIGetTvFormat() == 1)
    {
        tick = lbl_803A5D60.retraceCount * frame;
        lbl_803A5D60.curCount = tick / 5000;
    }
    else
    {
        tick = lbl_803A5D60.retraceCount * frame;
        lbl_803A5D60.curCount = tick / 0x176a;
    }

    if (lbl_803A5D60.prevCount != lbl_803A5D60.curCount)
    {
        lbl_803A5D60.prevCount = lbl_803A5D60.curCount;
        return TRUE;
    }
returnFalse:
    return FALSE;
}

/* .bss glue 0x803A5CCC-0x803A5F08 */
AttractMoviePlayer lbl_803A5D60;
char gPicMenuDvdReadBuffer[0x40];
u8 lbl_803A5CEC[0x34];
OSMessageQueue lbl_803A5CCC[1];

/* title-menu text entry tables referenced via extern by dll_0035_saveselectscreen; owned here by link order */

u8 lbl_8031A4B0[0xB4] = {
    0xFF, 0xFF, 0x00, 0x18, 0x00, 0x82, 0x00, 0xB2, 0x01, 0x40, 0x00, 0x59, 0x00, 0xAA, 0x00, 0x00, 0xFF, 0xFF,
    0xFF, 0xFF, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x19, 0x00, 0x82, 0x00, 0xCC, 0x01, 0x40, 0x00, 0x59,
    0x00, 0xC4, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xFF,
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x1A, 0x00, 0x82,
    0x00, 0xE6, 0x01, 0x40, 0x00, 0x59, 0x00, 0xDE, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

u8 lbl_8031A564[0x78] = {
    0x03, 0xD5, 0x00, 0x1D, 0x00, 0x3A, 0x01, 0x53, 0x00, 0x00, 0x00, 0x3A, 0x01, 0x47, 0x00, 0x00, 0xFF, 0xFF,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x05, 0x04, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xD6, 0x00, 0x1E, 0x00, 0x3A, 0x01, 0x53, 0x00, 0x00, 0x00, 0x3A,
    0x01, 0x47, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x05, 0x04, 0x00, 0xFF, 0xFF, 0xFF,
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

u8 lbl_8031A5DC[0x3C] = {
    0xFF, 0xFF, 0x00, 0x02, 0x00, 0x3A, 0x01, 0x53, 0x00, 0x00, 0x00, 0x3A, 0x01, 0x47, 0x00,
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x05, 0x04, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

u8 lbl_8031A618[0x3C] = {
    0xFF, 0xFF, 0x00, 0x02, 0x01, 0x40, 0x01, 0x7E, 0x00, 0x00, 0x01, 0x40, 0x01, 0x72, 0x00,
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x04, 0x00, 0x05, 0x04, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

u8 lbl_8031A654[0x168] = {
    0x03, 0xD5, 0x00, 0x17, 0x00, 0x82, 0x00, 0xB2, 0x01, 0x40, 0x00, 0x59, 0x00, 0xAA, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
    0xFF, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x9E, 0x00, 0x19, 0x00, 0x82, 0x00, 0xB2, 0x01, 0x40, 0x00, 0x59, 0x00, 0xAA, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x9F, 0x00, 0x1A, 0x00, 0x82, 0x00, 0xCC, 0x01, 0x40, 0x00, 0x59, 0x00,
    0xC4, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0xFF, 0xFF, 0xFF, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xA0, 0x00, 0x1B, 0x00, 0x82, 0x00, 0xE6, 0x01, 0x40,
    0x00, 0x59, 0x00, 0xDE, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0xFF,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xA1, 0x00, 0x1C, 0x00, 0x82, 0x00,
    0xE6, 0x01, 0x40, 0x00, 0x59, 0x00, 0xDE, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x05, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xA2, 0x00, 0x1D,
    0x00, 0x82, 0x00, 0xE6, 0x01, 0x40, 0x00, 0x59, 0x00, 0xDE, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
