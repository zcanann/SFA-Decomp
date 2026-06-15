#include "dolphin/ai.h"
#include "dolphin/os.h"
#include "dolphin/vi.h"
#include "main/dll/FRONT/attract_movie.h"

extern void* memset(void* dst, int value, uint size);
extern void* memcpy(void* dst, const void* src, uint size);
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern undefined4 PopDecodedAudioBuffer(int flags);
extern void PushFreeAudioBuffer(void* message);
extern undefined4 GXSetTexCoordGen2();
extern undefined4 GXSetNumTexGens();
extern undefined4 GXSetCullMode();
extern undefined4 GXInitTexObj();
extern undefined4 GXInitTexObjLOD();
extern undefined4 GXLoadTexObj();
extern undefined4 GXSetNumIndStages();
extern undefined4 GXSetTevDirect();
extern undefined4 GXSetTevColorIn();
extern undefined4 GXSetTevAlphaIn();
extern undefined4 GXSetTevColorOp();
extern undefined4 GXSetTevAlphaOp();
extern undefined4 GXSetTevColorS10();
extern undefined4 GXSetTevKColor();
extern undefined4 GXSetTevKColorSel();
extern undefined4 GXSetTevKAlphaSel();
extern undefined4 GXSetTevSwapMode();
extern undefined4 GXSetTevSwapModeTable();
extern undefined4 GXSetAlphaCompare();
extern undefined4 GXSetTevOrder();
extern undefined4 GXSetNumTevStages();
extern undefined4 GXSetBlendMode();
extern undefined4 GXSetColorUpdate();
extern undefined4 GXSetAlphaUpdate();
extern void fn_8004C7AC(void* yTexture, void* uTexture, void* vTexture, int width, int height);
extern u8* ObjModel_GetRenderOp(undefined4 model, undefined4 idx);
extern void PushFreeTextureSet(OSMessage msg);

extern u16 gAttractMovieVolumeScale[];
extern undefined4 lbl_803E1D30;
extern undefined4 lbl_803E1D34;
extern undefined4 lbl_803E1D38;
extern undefined4 lbl_803E1D3C;
extern undefined4 lbl_803E1D40;
extern f32 lbl_803E1D44;
extern s32 gAttractMovieState;
extern s32 lbl_803DD660;
extern AIDCallback lbl_803DD668;
extern s32 lbl_803DD66C;
extern u32 lbl_803DD670;
extern u32 lbl_803DD674;
extern u32 lbl_803DD678;
extern f32 lbl_803E1D50;
extern char lbl_803A57C0[0x50C];
extern OSMessageQueue lbl_803A5CCC[1];

void THPPlayerDrawCurrentFrame(void* yBuf, void* uBuf, void* vBuf, uint width, uint height)
{
    uint halfWidth;
    uint halfHeight;
    double lod;
    undefined4 kColor0;
    undefined4 kColor1;
    undefined4 kColor2;
    undefined4 tevColorS10[2];
    uint yTexObj[8];
    uint uTexObj[8];
    uint vTexObj[8];

    gxSetZMode_(1, 3, 1);
    GXSetBlendMode(0, 1, 0, 0);
    GXSetColorUpdate(1);
    GXSetAlphaUpdate(0);
    GXSetCullMode(2);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
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
    tevColorS10[0] = lbl_803E1D30;
    tevColorS10[1] = lbl_803E1D34;
    GXSetTevColorS10(1, (short*)tevColorS10);
    kColor0 = lbl_803E1D38;
    GXSetTevKColor(0, (byte*)&kColor0);
    kColor1 = lbl_803E1D3C;
    GXSetTevKColor(1, (byte*)&kColor1);
    kColor2 = lbl_803E1D40;
    GXSetTevKColor(2, (byte*)&kColor2);
    GXSetTevSwapModeTable(0, 0, 1, 2, 3);
    GXInitTexObj(yTexObj, yBuf, width & 0xffff, height & 0xffff, 1, 0, 0,
                 '\0');
    lod = (double)lbl_803E1D44;
    GXInitTexObjLOD(yTexObj, 0, 0, lod, lod, lod, 0, '\0', 0);
    GXLoadTexObj(yTexObj, 0);
    halfWidth = (int)(short)width >> 1;
    halfHeight = (int)(short)height >> 1;
    GXInitTexObj(uTexObj, uBuf, halfWidth & 0xffff, halfHeight & 0xffff, 1, 0, 0, '\0');
    lod = (double)lbl_803E1D44;
    GXInitTexObjLOD(uTexObj, 0, 0, lod, lod, lod, 0, '\0', 0);
    GXLoadTexObj(uTexObj, 1);
    GXInitTexObj(vTexObj, vBuf, halfWidth & 0xffff, halfHeight & 0xffff, 1, 0, 0, '\0');
    lod = (double)lbl_803E1D44;
    GXInitTexObjLOD(vTexObj, 0, 0, lod, lod, lod, 0, '\0', 0);
    GXLoadTexObj(vTexObj, 2);
    return;
}

BOOL Movie_SetVolumeFade(int volume, int fadeFrames)
{
    BOOL interrupts;
    f32 targetVolume;
    int rampCount;

    if ((lbl_803A5D60.isOpen != 0) && (lbl_803A5D60.audioExists != 0))
    {
        if (volume > 0x7f)
        {
            volume = 0x7f;
        }
        if (volume < 0)
        {
            volume = 0;
        }
        if (fadeFrames > 60000)
        {
            fadeFrames = 60000;
        }
        if (fadeFrames < 0)
        {
            fadeFrames = 0;
        }

        interrupts = OSDisableInterrupts();
        targetVolume = (f32)volume;
        lbl_803A5D60.targetVolume = targetVolume;
        if (fadeFrames != 0)
        {
            rampCount = fadeFrames << 5;
            lbl_803A5D60.rampCount = rampCount;
            lbl_803A5D60.deltaVolume = (targetVolume - lbl_803A5D60.curVolume) / (f32)rampCount;
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

void AttractMovieAudio_Mix(s16* destination, s16* source, uint sampleCount)
{
    ushort volumeScale;
    float volume;
    uint validSamples;
    int mixed;
    short* audioPtr;
    uint remain;

    if (source != (short*)0x0)
    {
        if (((lbl_803A5D60.isOpen == 0) || (lbl_803A5D60.internalState != 2)) || (lbl_803A5D60.audioExists == 0))
        {
            memcpy(destination, source, sampleCount << 2);
        }
        else
        {
            do
            {
                do
                {
                    if (lbl_803A5D60.curAudioBuffer == NULL)
                    {
                        lbl_803A5D60.curAudioBuffer = (AttractMovieAudioBuffer*)PopDecodedAudioBuffer(0);
                        if (lbl_803A5D60.curAudioBuffer == NULL)
                        {
                            memcpy(destination, source, sampleCount << 2);
                            return;
                        }
                        lbl_803A5D60.curAudioFrameNumber = lbl_803A5D60.curAudioBuffer->frameNumber;
                    }
                    validSamples = lbl_803A5D60.curAudioBuffer->validSample;
                }
                while (validSamples == 0);
                if (sampleCount <= validSamples)
                {
                    validSamples = sampleCount;
                }
                audioPtr = lbl_803A5D60.curAudioBuffer->curPtr;
                for (remain = validSamples; remain != 0; remain = remain - 1)
                {
                    volume = lbl_803A5D60.targetVolume;
                    if (lbl_803A5D60.rampCount != 0)
                    {
                        lbl_803A5D60.rampCount = lbl_803A5D60.rampCount + -1;
                        volume = lbl_803A5D60.curVolume + lbl_803A5D60.deltaVolume;
                    }
                    lbl_803A5D60.curVolume = volume;
                    volumeScale = gAttractMovieVolumeScale[(int)lbl_803A5D60.curVolume];
                    mixed = (int)*source + ((int)((uint)volumeScale * (int)*audioPtr) >> 0xf);
                    if (mixed < -0x8000)
                    {
                        mixed = -0x8000;
                    }
                    if (0x7fff < mixed)
                    {
                        mixed = 0x7fff;
                    }
                    *destination = (short)mixed;
                    mixed = (int)source[1] + ((int)((uint)volumeScale * (int)audioPtr[1]) >> 0xf);
                    if (mixed < -0x8000)
                    {
                        mixed = -0x8000;
                    }
                    if (0x7fff < mixed)
                    {
                        mixed = 0x7fff;
                    }
                    destination[1] = (short)mixed;
                    destination = destination + 2;
                    source = source + 2;
                    audioPtr = audioPtr + 2;
                }
                sampleCount = sampleCount - validSamples;
                lbl_803A5D60.curAudioBuffer->validSample = lbl_803A5D60.curAudioBuffer->validSample - validSamples;
                lbl_803A5D60.curAudioBuffer->curPtr = audioPtr;
                if (lbl_803A5D60.curAudioBuffer->validSample == 0)
                {
                    PushFreeAudioBuffer(lbl_803A5D60.curAudioBuffer);
                    lbl_803A5D60.curAudioBuffer = NULL;
                }
            }
            while (sampleCount != 0);
        }
    }
    else if (((lbl_803A5D60.isOpen == 0) || (lbl_803A5D60.internalState != 2)) || (lbl_803A5D60.audioExists == 0))
    {
        memset(destination, 0, sampleCount << 2);
    }
    else
    {
        do
        {
            do
            {
                if (lbl_803A5D60.curAudioBuffer == NULL)
                {
                    lbl_803A5D60.curAudioBuffer = (AttractMovieAudioBuffer*)PopDecodedAudioBuffer(0);
                    if (lbl_803A5D60.curAudioBuffer == NULL)
                    {
                        memset(destination, 0, sampleCount << 2);
                        return;
                    }
                    lbl_803A5D60.curAudioFrameNumber = lbl_803A5D60.curAudioBuffer->frameNumber;
                }
                validSamples = lbl_803A5D60.curAudioBuffer->validSample;
            }
            while (validSamples == 0);
            if (sampleCount <= validSamples)
            {
                validSamples = sampleCount;
            }
            audioPtr = lbl_803A5D60.curAudioBuffer->curPtr;
            for (remain = validSamples; remain != 0; remain = remain - 1)
            {
                volume = lbl_803A5D60.targetVolume;
                if (lbl_803A5D60.rampCount != 0)
                {
                    lbl_803A5D60.rampCount = lbl_803A5D60.rampCount + -1;
                    volume = lbl_803A5D60.curVolume + lbl_803A5D60.deltaVolume;
                }
                lbl_803A5D60.curVolume = volume;
                volumeScale = gAttractMovieVolumeScale[(int)lbl_803A5D60.curVolume];
                mixed = (int)((uint)volumeScale * (int)*audioPtr) >> 0xf;
                if (mixed < -0x8000)
                {
                    mixed = -0x8000;
                }
                if (0x7fff < mixed)
                {
                    mixed = 0x7fff;
                }
                *destination = (short)mixed;
                mixed = (int)((uint)volumeScale * (int)audioPtr[1]) >> 0xf;
                if (mixed < -0x8000)
                {
                    mixed = -0x8000;
                }
                if (0x7fff < mixed)
                {
                    mixed = 0x7fff;
                }
                destination[1] = (short)mixed;
                destination = destination + 2;
                audioPtr = audioPtr + 2;
            }
            sampleCount = sampleCount - validSamples;
            lbl_803A5D60.curAudioBuffer->validSample = lbl_803A5D60.curAudioBuffer->validSample - validSamples;
            lbl_803A5D60.curAudioBuffer->curPtr = audioPtr;
            if (lbl_803A5D60.curAudioBuffer->validSample == 0)
            {
                PushFreeAudioBuffer(lbl_803A5D60.curAudioBuffer);
                lbl_803A5D60.curAudioBuffer = NULL;
            }
        }
        while (sampleCount != 0);
    }
    return;
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
            lbl_803DD674 = AIGetDMAStartAddr() + 0x80000000;
        }
        else
        {
            lbl_803DD668();
            lbl_803DD670 = AIGetDMAStartAddr() + 0x80000000;
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

uint AttractMovie_DrawTextureCallback(undefined4 param_1, undefined4* modelPtr, undefined4 renderOpIdx)
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
