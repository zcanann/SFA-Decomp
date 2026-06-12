#include "main/dll/FRONT/dll_3B.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/screen_transition.h"
#include "dolphin/os.h"
#include "dolphin/thp/THPAudio.h"

extern void audioSetVolumes(int channel, int volume, int frames, int arg3, int arg4);
extern void audioStopByMask(int mask);
extern void audioFn_8000b694(int arg);
extern int getUiDllFn_80014930(void);
extern void gameTimerStop(void);
extern void gameTextLoadDir(int dirId);
extern void setDrawLights(int arg);
extern void setIsOvercast(int arg);
extern void saveFn_8007d960(int);
extern void envFxActFn_800887f8(int arg);
extern void Movie_SetVolumeFade(int volume, int fadeFrames);
extern void setLinkIsRotated(void);
extern void titleScreenPositionElements(f32 x, f32 y);
extern void titleScreenFn_801368a4(u8 arg);
extern void* PopReadedBuffer(void);
extern void PushReadedBuffer2(void* arg);

extern TitleMenuTextEntry sNAttractModeStringBlock[1];
extern TitleMenuTextEntry lbl_8031A214[4];
extern OSMessageQueue lbl_803A4460;
extern OSMessageQueue lbl_803A4480;
extern OSThread lbl_803A54A0;
extern u8* lbl_803DD498;
extern u8 lbl_803DB424;
extern s32 gAttractMovieState;
extern u8 gTitleMenuSelection;
extern u8 gTitleMenuSelectionFade;
extern u8 gAttractMoviePreparePending;
extern u8 gAttractMovieAutoplayEnabled;
extern s32 gTitleMenuInputCooldown;
extern u8 gAttractMovieReplayCountdown;
extern u8 gAttractMovieRetraceCountdown;
extern u8 gTitleMenuReadyForInput;
extern u8 gAttractMoviePlaybackEnabled;
extern s8 gTitleMenuNextDllId;
extern s8 gTitleMenuLoadDelay;
extern u8 gTitleMenuPanelOpen;
extern u8 gAttractMovieLoopCompleted;
extern s32 gAttractMovieIdleFrameCount;
extern s32 gAttractMovieAudioThreadActive;
extern TitleMenuControl* gScreenTransitionInterface;
extern TitleMenuControl* gTitleMenuLinkInterface;
extern f32 lbl_803E1D10;
extern f32 lbl_803E1D18;

/*
 * --INFO--
 *
 * Function: TitleMenu_initialise
 * EN v1.0 Address: 0x80116F84
 * EN v1.0 Size: 904b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void TitleMenu_initialise(void);

void* PopDecodedAudioBuffer(int flags)
{
    void* message;

    if (OSReceiveMessage(&lbl_803A4460, &message, flags) == 1)
    {
        return message;
    }
    return NULL;
}

void PushFreeAudioBuffer(void* message)
{
    OSSendMessage(&lbl_803A4480, message, 0);
}

#pragma dont_inline on
void AttractMovieAudio_Decode(void* readBufferArg)
{
    u32* audioFrameSizes;
    AttractMovieReadBuffer* readBuffer;
    AttractMovieAudioBuffer* audioBuf;
    u8* audioFrame;
    u32 track;

    readBuffer = (AttractMovieReadBuffer*)readBufferArg;
    audioFrameSizes = (u32*)(readBuffer->ptr + 8);
    audioFrame = readBuffer->ptr + (lbl_803A5D60.compInfo.mNumComponents * sizeof(u32)) + 8;
    {
        AttractMovieAudioBuffer* received;
        OSReceiveMessage(&lbl_803A4480, &received, 1);
        audioBuf = received;
    }
    for (track = 0; track < lbl_803A5D60.compInfo.mNumComponents; track++)
    {
        switch (lbl_803A5D60.compInfo.mFrameComp[track])
        {
        case 1:
            audioBuf->validSample = THPAudioDecode(audioBuf->buffer, audioFrame, 0);
            audioBuf->curPtr = audioBuf->buffer;
            audioBuf->frameNumber = readBuffer->frameNumber;
            OSSendMessage(&lbl_803A4460, audioBuf, 1);
            break;
        }
        audioFrame += *audioFrameSizes;
        audioFrameSizes++;
    }
}
#pragma dont_inline reset

void* AudioDecoderForOnMemory(void* param)
{
    register int frame;
    register AttractMoviePlayer* player;
    int stride;
    u32 framesPerGroup;
    u32 frameInGroup;
    AttractMovieReadBuffer readBuffer;

    player = &lbl_803A5D60;
    stride = player->frameStride;
    readBuffer.ptr = param;
    frame = 0;
    while (true)
    {
        readBuffer.frameNumber = frame;
        AttractMovieAudio_Decode(&readBuffer);
        framesPerGroup = player->header.mNumFrames;
        frameInGroup = (frame + player->initReadFrame) % framesPerGroup;
        if (frameInGroup == (framesPerGroup - 1))
        {
            if ((player->playFlags & 1) != 0)
            {
                stride = *(int*)readBuffer.ptr;
                readBuffer.ptr = player->loopFrame;
            }
            else
            {
                OSSuspendThread(&lbl_803A54A0);
            }
        }
        else
        {
            int newStride = *(int*)readBuffer.ptr;
            readBuffer.ptr += stride;
            stride = newStride;
        }
        frame++;
    }
}

void* AudioDecoder(void* param)
{
    void* token;

    (void)param;
    while (true)
    {
        token = PopReadedBuffer();
        AttractMovieAudio_Decode(token);
        PushReadedBuffer2(token);
    }
}

void AudioDecodeThreadCancel(void)
{
    if (gAttractMovieAudioThreadActive != 0)
    {
        OSCancelThread(&lbl_803A54A0);
        gAttractMovieAudioThreadActive = 0;
    }
}

void AudioDecodeThreadStart(void)
{
    if (gAttractMovieAudioThreadActive != 0)
    {
        OSResumeThread(&lbl_803A54A0);
    }
}
