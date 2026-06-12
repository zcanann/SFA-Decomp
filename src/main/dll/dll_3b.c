#include "main/dll/FRONT/dll_3B.h"
#include "dolphin/os.h"
#include "dolphin/thp/THPAudio.h"

extern void* PopReadedBuffer(void);
extern void PushReadedBuffer2(void* arg);

extern OSMessageQueue lbl_803A4460;
extern OSMessageQueue lbl_803A4480;
extern OSThread lbl_803A54A0;
extern s32 gAttractMovieAudioThreadActive;

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
