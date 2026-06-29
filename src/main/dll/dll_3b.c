/*
 * dll_3b (FRONT 0x3B) - attract-movie audio decode thread support.
 *
 * Backs the THP attract-movie player (AttractMoviePlayer lbl_803A5D60,
 * attract_movie.h). A worker thread (lbl_803A54A0) decodes audio frames
 * out of a THP stream and hands finished sample buffers to the player's
 * mixer through two message queues:
 *   lbl_803A4460 - decoded audio buffers ready for playback (producer here,
 *                  drained via PopDecodedAudioBuffer / n_options.c)
 *   lbl_803A4480 - free buffers returned for reuse (PushFreeAudioBuffer)
 *
 * AttractMovieAudio_Decode pulls the audio THP frame-component out of a read
 * buffer, runs THPAudioDecode into a free AttractMovieAudioBuffer, and posts
 * it. Two thread entry points feed it: AudioDecoderForOnMemory walks an
 * in-memory THP (honoring the loop flag), AudioDecoder consumes streamed read
 * buffers from picmenu's reader queue. ThreadStart/ThreadCancel are the
 * resume/cancel hooks used by dll_3e.
 */
#include "main/dll/FRONT/dll_3B.h"
#include "dolphin/os.h"
#include "dolphin/thp/THPAudio.h"

/* THP frame-component type id for the audio track (vs 0 = video). */
#define THP_FRAME_COMP_AUDIO 1

extern void* PopReadedBuffer(void);
extern void PushReadedBuffer2(void* arg);

extern OSMessageQueue lbl_803A4460; /* ready-buffer queue */
extern OSMessageQueue lbl_803A4480; /* free-buffer queue */
extern OSThread lbl_803A54A0;       /* audio decode worker thread */
extern int gAttractMovieAudioThreadActive;

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
    OSSendMessage(&lbl_803A4480, message, OS_MESSAGE_NOBLOCK);
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
        OSReceiveMessage(&lbl_803A4480, &received, OS_MESSAGE_BLOCK);
        audioBuf = received;
    }
    for (track = 0; track < lbl_803A5D60.compInfo.mNumComponents; track++)
    {
        switch (lbl_803A5D60.compInfo.mFrameComp[track])
        {
        case THP_FRAME_COMP_AUDIO:
            audioBuf->validSample = THPAudioDecode(audioBuf->buffer, audioFrame, 0);
            audioBuf->curPtr = audioBuf->buffer;
            audioBuf->frameNumber = readBuffer->frameNumber;
            OSSendMessage(&lbl_803A4460, audioBuf, OS_MESSAGE_BLOCK);
            break;
        }
        audioFrame += *audioFrameSizes;
        audioFrameSizes++;
    }
}
#pragma dont_inline reset

void* AudioDecoderForOnMemory(void* param)
{
    register AttractMoviePlayer* player;
    int stride;
    u32 framesPerGroup;
    u32 frameInGroup;
    register int frame;
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
    return NULL;
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
    return NULL;
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
