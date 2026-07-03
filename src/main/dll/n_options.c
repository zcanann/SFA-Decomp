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
#include "dolphin/os.h"
#include "dolphin/vi.h"
#include "main/dll/FRONT/attract_movie.h"
#include "string.h"
#include "main/dll/FRONT/dll_3B.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXBump.h"
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern void GXSetTexCoordGen2(GXTexCoordID dst_coord, GXTexGenType func, GXTexGenSrc src_param, u32 mtx, GXBool normalize, u32 pt_texmtx);
extern void GXSetNumTexGens(u8 nTexGens);
extern void GXInitTexObj(GXTexObj* obj, void* image_ptr, u16 width, u16 height, GXTexFmt format, GXTexWrapMode wrap_s, GXTexWrapMode wrap_t, GXBool mipmap);
extern void GXInitTexObjLOD(GXTexObj* obj, GXTexFilter min_filt, GXTexFilter mag_filt, f32 min_lod, f32 max_lod, f32 lod_bias, u8 bias_clamp, u8 do_edge_lod, GXAnisotropy max_aniso);



extern void GXSetTevColorIn(GXTevStageID stage, GXTevColorArg a, GXTevColorArg b, GXTevColorArg c, GXTevColorArg d);
extern void GXSetTevAlphaIn(GXTevStageID stage, GXTevAlphaArg a, GXTevAlphaArg b, GXTevAlphaArg c, GXTevAlphaArg d);
extern void GXSetTevColorOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp, GXTevRegID out_reg);
extern void GXSetTevAlphaOp(GXTevStageID stage, GXTevOp op, GXTevBias bias, GXTevScale scale, GXBool clamp, GXTevRegID out_reg);
extern u32 GXSetTevColorS10();
extern u32 GXSetTevKColor();
extern void GXSetTevKColorSel(GXTevStageID stage, GXTevKColorSel sel);
extern void GXSetTevKAlphaSel(GXTevStageID stage, GXTevKAlphaSel sel);
extern void GXSetTevSwapMode(GXTevStageID stage, GXTevSwapSel ras_sel, GXTevSwapSel tex_sel);
extern void GXSetTevSwapModeTable(GXTevSwapSel table, GXTevColorChan red, GXTevColorChan green, GXTevColorChan blue, GXTevColorChan alpha);
extern void GXSetAlphaCompare(GXCompare comp0, u8 ref0, GXAlphaOp op, GXCompare comp1, u8 ref1);
extern void GXSetTevOrder(GXTevStageID stage, GXTexCoordID coord, GXTexMapID map, GXChannelID color);
extern void GXSetNumTevStages(u8 nStages);
extern void fn_8004C7AC(void* yTexture, void* uTexture, void* vTexture, int width, int height);
extern u8* ObjModel_GetRenderOp(int model, int idx);
extern void PushFreeTextureSet(OSMessage msg);
extern u16 gAttractMovieVolumeScale[];
typedef struct { u32 a; u32 b; } TevColorS10Pair;
extern TevColorS10Pair lbl_803E1D30; /* TEV color-S10 / k-color constants */
extern u32 lbl_803E1D38;
extern u32 lbl_803E1D3C;
extern u32 lbl_803E1D40;
extern s32 gAttractMovieState;
extern s32 lbl_803DD660;       /* texture-set free queue active */
extern AIDCallback lbl_803DD668; /* AI DMA done callback */
extern s32 lbl_803DD66C;       /* DMA callback phase */
extern u32 lbl_803DD670;       /* previous/pending DMA source addr */
extern u32 lbl_803DD674;       /* queued next DMA source addr */
extern u32 lbl_803DD678;       /* AI DMA double-buffer index */
extern f32 lbl_803E1D50;       /* playback time accumulator */
char lbl_803A57C0[0x50C]; /* AI DMA double buffer */
extern OSMessageQueue lbl_803A5CCC[1]; /* spent texture-set queue */

#define MOVIE_VOLUME_MAX 0x7f
#define MOVIE_FADE_FRAMES_MAX 60000
#define S16_MIN (-0x8000)
#define S16_MAX 0x7fff

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
    GXSetColorUpdate(1);
    GXSetAlphaUpdate(0);
    GXSetCullMode(GX_CULL_BACK);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetNumTexGens(2);
    GXSetTexCoordGen2(0, 1, 4, 0x3c, 0, 0x7d);
    GXSetTexCoordGen2(1, 1, 4, 0x3c, 0, 0x7d);
    GXSetNumTevStages(4);
    GXSetNumIndStages(0);
    GXSetTevOrder(0, 1, 1, 0xff);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xf, 8, 0xe, 2);
    GXSetTevColorOp(0, 0, 0, 0, 0, 0);
    GXSetTevAlphaIn(0, 7, 4, 6, 1);
    GXSetTevAlphaOp(0, 1, 0, 0, 0, 0);
    GXSetTevKColorSel(0, 0xc);
    GXSetTevKAlphaSel(0, 0x1c);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevOrder(1, 1, 2, 0xff);
    GXSetTevDirect(1);
    GXSetTevColorIn(1, 0xf, 8, 0xe, 0);
    GXSetTevColorOp(1, 0, 0, 1, 0, 0);
    GXSetTevAlphaIn(1, 7, 4, 6, 0);
    GXSetTevAlphaOp(1, 1, 0, 0, 0, 0);
    GXSetTevKColorSel(1, 0xd);
    GXSetTevKAlphaSel(1, 0x1d);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevOrder(2, 0, 0, 0xff);
    GXSetTevDirect(2);
    GXSetTevColorIn(2, 0xf, 8, 0xc, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaIn(2, 4, 7, 7, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevOrder(3, 0xff, 0xff, 0xff);
    GXSetTevDirect(3);
    GXSetTevColorIn(3, 1, 0, 0xe, 0xf);
    GXSetTevColorOp(3, 0, 0, 0, 1, 0);
    GXSetTevAlphaIn(3, 7, 7, 7, 7);
    GXSetTevAlphaOp(3, 0, 0, 0, 1, 0);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevKColorSel(3, 0xe);
    tevColorS10 = lbl_803E1D30;
    GXSetTevColorS10(1, &tevColorS10);
    kColor0 = lbl_803E1D38;
    GXSetTevKColor(0, &kColor0);
    kColor1 = lbl_803E1D3C;
    GXSetTevKColor(1, &kColor1);
    kColor2 = lbl_803E1D40;
    GXSetTevKColor(2, &kColor2);
    GXSetTevSwapModeTable(0, 0, 1, 2, 3);
    GXInitTexObj(&yTexObj, yBuf, width, height, 1, 0, 0, 0);
    GXInitTexObjLOD(&yTexObj, 0, 0, 0.0f, 0.0f, 0.0f, 0, 0, 0);
    GXLoadTexObj(&yTexObj, 0);
    GXInitTexObj(&uTexObj, uBuf, halfWidth = (short)width >> 1, halfHeight = (short)height >> 1, 1, 0, 0, 0);
    GXInitTexObjLOD(&uTexObj, 0, 0, 0.0f, 0.0f, 0.0f, 0, 0, 0);
    GXLoadTexObj(&uTexObj, 1);
    GXInitTexObj(&vTexObj, vBuf, halfWidth, halfHeight, 1, 0, 0, 0);
    GXInitTexObjLOD(&vTexObj, 0, 0, 0.0f, 0.0f, 0.0f, 0, 0, 0);
    GXLoadTexObj(&vTexObj, 2);
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
                }
                while (validSamples == 0);
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
            }
            while (validSamples == 0);
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
        fn_8004C7AC(textureSet->yTexture, textureSet->uTexture, textureSet->vTexture,
                    (s16)lbl_803A5D60.videoInfo.xSize, (s16)lbl_803A5D60.videoInfo.ySize);
    }
}

BOOL AttractMovie_DrawTextureCallback(int unused, u32* modelPtr, u32 renderOpIdx)
{
    AttractMovieTextureSet* textureSet;
    u8* renderOp;

    if (modelPtr != NULL)
    {
        renderOp = ObjModel_GetRenderOp(*modelPtr, renderOpIdx);
    }
    else
    {
        renderOp = NULL;
    }

    if (((renderOp == NULL) || (renderOp[0x29] == 1)) && (gAttractMovieState == 2))
    {
        textureSet = lbl_803A5D60.curTextureSet;
        THPPlayerDrawCurrentFrame(textureSet->yTexture, textureSet->uTexture, textureSet->vTexture,
                                  (s16)lbl_803A5D60.videoInfo.xSize,
                                  (s16)lbl_803A5D60.videoInfo.ySize);
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
