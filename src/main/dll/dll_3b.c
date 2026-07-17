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
 * buffers from picmenu's reader queue. AudioDecodeThreadStart/
 * AudioDecodeThreadCancel are the resume/cancel hooks used by dll_3e.
 */
#include "main/dll/FRONT/dll_3B.h"
#include "dolphin/os.h"
#include "dolphin/thp/THPAudio.h"
#include "main/dll/FRONT/picmenu.h"

/* THP frame-component type id for the audio track (vs 0 = video). */
#define THP_FRAME_COMP_AUDIO 1

/*
 * Per-frame layout in a read buffer: an 8-byte frame header, then one u32
 * component size per component, then the component payloads back-to-back.
 */
#define THP_FRAME_HEADER_SIZE 8

extern int gAttractMovieAudioThreadActive;

typedef struct AttractMovieFreeQueueAndStack
{
    OSMessageQueue queue;      /* free-buffer queue */
    u32 threadStack[0x1000 / 4];
} AttractMovieFreeQueueAndStack;

typedef struct AttractMovieDecodeThread
{
    OSThread thread; /* audio decode worker thread */
    u32 pad310[0x10 / 4];
} AttractMovieDecodeThread;

OSMessageQueue lbl_803A4460; /* ready-buffer queue */
AttractMovieFreeQueueAndStack lbl_803A4480;
AttractMovieDecodeThread lbl_803A54A0;

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
    OSSendMessage(&lbl_803A4480.queue, message, OS_MESSAGE_NOBLOCK);
}

#pragma dont_inline on
void AttractMovieAudio_Decode(void* readBufferArg)
{
    u32* audioFrameSizes;
    AttractMovieReadBuffer* readBuffer;
    AttractMovieAudioBuffer* audioBuf[1];
    u8* audioFrame;
    u32 track;

    readBuffer = (AttractMovieReadBuffer*)readBufferArg;
    audioFrameSizes = (u32*)(readBuffer->ptr + THP_FRAME_HEADER_SIZE);
    audioFrame = readBuffer->ptr + (lbl_803A5D60.compInfo.mNumComponents * sizeof(u32)) + THP_FRAME_HEADER_SIZE;
    {
        AttractMovieAudioBuffer* received;
        OSReceiveMessage(&lbl_803A4480.queue, &received, OS_MESSAGE_BLOCK);
        audioBuf[0] = received;
    }
    for (track = 0; track < lbl_803A5D60.compInfo.mNumComponents; track++)
    {
        switch (lbl_803A5D60.compInfo.mFrameComp[track])
        {
        case THP_FRAME_COMP_AUDIO:
            audioBuf[0]->validSample = THPAudioDecode(audioBuf[0]->buffer, audioFrame, 0);
            audioBuf[0]->curPtr = audioBuf[0]->buffer;
            audioBuf[0]->frameNumber = readBuffer->frameNumber;
            OSSendMessage(&lbl_803A4460, audioBuf[0], OS_MESSAGE_BLOCK);
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
                OSSuspendThread(&lbl_803A54A0.thread);
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
        OSCancelThread(&lbl_803A54A0.thread);
        gAttractMovieAudioThreadActive = 0;
    }
}

void AudioDecodeThreadStart(void)
{
    if (gAttractMovieAudioThreadActive != 0)
    {
        OSResumeThread(&lbl_803A54A0.thread);
    }
}
