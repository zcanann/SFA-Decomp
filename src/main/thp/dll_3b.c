#include "main/dll/FRONT/dll_3B.h"
#include "main/thp_read.h"
#include "dolphin/os.h"
#include "main/dll/FRONT/picmenu.h"
#include "dolphin/os/OSThread.h"
#include "dolphin/thp/THPAudio.h"
#include "main/audio_decode_thread.h"

/*
 * dll_3b (FRONT 0x3B) - attract-movie audio decode thread support.
 *
 * Backs the THP attract-movie player (AttractMoviePlayer gAttractMoviePlayer,
 * attract_movie.h). A worker thread decodes audio frames
 * out of a THP stream and hands finished sample buffers to the player's
 * mixer through two message queues:
 *   gAttractMovieDecodedAudioQueue - decoded buffers ready for playback
 *   gAttractMovieFreeAudioQueueAndStack - free buffers returned for reuse
 *
 * AttractMovieAudio_Decode pulls the audio THP frame-component out of a read
 * buffer, runs THPAudioDecode into a free AttractMovieAudioBuffer, and posts
 * it. Two thread entry points feed it: AudioDecoderForOnMemory walks an
 * in-memory THP (honoring the loop flag), AudioDecoder consumes streamed read
 * buffers from picmenu's reader queue. AudioDecodeThreadStart/
 * AudioDecodeThreadCancel are the resume/cancel hooks used by dll_3e.
 */

/* THP frame-component type id for the audio track (vs 0 = video). */
#define THP_FRAME_COMP_AUDIO 1

/*
 * Per-frame layout in a read buffer: an 8-byte frame header, then one u32
 * component size per component, then the component payloads back-to-back.
 */
#define THP_FRAME_HEADER_SIZE 8

s32 gAttractMovieAudioThreadActive;

void* PopDecodedAudioBuffer(int flags)
{
    void* message;

    if (OSReceiveMessage(&gAttractMovieDecodedAudioQueue, &message, flags) == 1)
    {
        return message;
    }
    return NULL;
}

void PushFreeAudioBuffer(void* message)
{
    OSSendMessage(&gAttractMovieFreeAudioQueueAndStack.queue, message, OS_MESSAGE_NOBLOCK);
}

static void AttractMovieAudio_Decode(AttractMovieReadBuffer* readBufferArg) {
    u32* audioFrameSizes;
    AttractMovieReadBuffer* readBuffer;
    AttractMovieAudioBuffer* audioBuf[1];
    u8* audioFrame;
    u32 track;

    readBuffer = readBufferArg;
    audioFrameSizes = (u32*)(readBuffer->ptr + THP_FRAME_HEADER_SIZE);
    audioFrame = readBuffer->ptr + (gAttractMoviePlayer.compInfo.mNumComponents * sizeof(u32)) + THP_FRAME_HEADER_SIZE;
    {
        AttractMovieAudioBuffer* received;
        OSReceiveMessage(&gAttractMovieFreeAudioQueueAndStack.queue, &received, OS_MESSAGE_BLOCK);
        audioBuf[0] = received;
    }
    for (track = 0; track < gAttractMoviePlayer.compInfo.mNumComponents; track++) {
        switch (gAttractMoviePlayer.compInfo.mFrameComp[track]) {
        case THP_FRAME_COMP_AUDIO:
            audioBuf[0]->validSample = THPAudioDecode(audioBuf[0]->buffer, audioFrame, 0);
            audioBuf[0]->curPtr = audioBuf[0]->buffer;
            audioBuf[0]->frameNumber = readBuffer->frameNumber;
            OSSendMessage(&gAttractMovieDecodedAudioQueue, audioBuf[0], OS_MESSAGE_BLOCK);
            break;
        }
        audioFrame += *audioFrameSizes;
        audioFrameSizes++;
    }
}

static void* AudioDecoderForOnMemory(void* param) {
    register AttractMoviePlayer* player;
    int stride;
    u32 framesPerGroup;
    u32 frameInGroup;
    register int frame;
    AttractMovieReadBuffer readBuffer;

    player = &gAttractMoviePlayer;
    stride = player->frameStride;
    readBuffer.ptr = param;
    frame = 0;
    while (true) {
        readBuffer.frameNumber = frame;
        AttractMovieAudio_Decode(&readBuffer);
        framesPerGroup = player->header.mNumFrames;
        frameInGroup = (frame + player->initReadFrame) % framesPerGroup;
        if (frameInGroup == (framesPerGroup - 1)) {
            if ((player->playFlags & 1) != 0) {
                stride = *(int*)readBuffer.ptr;
                readBuffer.ptr = player->loopFrame;
            } else {
                OSSuspendThread(&gAttractMovieAudioDecodeThread.thread);
            }
        } else {
            int newStride = *(int*)readBuffer.ptr;
            readBuffer.ptr += stride;
            stride = newStride;
        }
        frame++;
    }
    return NULL;
}

static void* AudioDecoder(void* param) {
    AttractMovieReadBuffer* token;

    (void)param;
    while (true) {
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
        OSCancelThread(&gAttractMovieAudioDecodeThread.thread);
        gAttractMovieAudioThreadActive = 0;
    }
}

void AudioDecodeThreadStart(void)
{
    if (gAttractMovieAudioThreadActive != 0)
    {
        OSResumeThread(&gAttractMovieAudioDecodeThread.thread);
    }
}

typedef struct AttractMovieAudioDecodeLayout
{
    AttractMovieAudioMessageStorage messages;
    OSMessageQueue decodedQueue;
    AttractMovieFreeQueueAndStack freeQueueAndStack;
    AttractMovieDecodeThread decodeThread;
} AttractMovieAudioDecodeLayout;

STATIC_ASSERT(offsetof(AttractMovieAudioDecodeLayout, decodedQueue) == 0x18);
STATIC_ASSERT(offsetof(AttractMovieAudioDecodeLayout, freeQueueAndStack) == 0x38);
STATIC_ASSERT(offsetof(AttractMovieAudioDecodeLayout, decodeThread) == 0x1058);
STATIC_ASSERT(sizeof(AttractMovieAudioDecodeLayout) == 0x1378);

BOOL CreateAudioDecodeThread(OSPriority priority, void* param)
{
    AttractMovieAudioDecodeLayout* context[1];
    context[0] = (AttractMovieAudioDecodeLayout*)&gAttractMovieAudioDecodeContext;

    if (param != NULL)
    {
        if (OSCreateThread(&context[0]->decodeThread.thread, AudioDecoderForOnMemory, param,
                           context[0]->freeQueueAndStack.threadStack +
                               ARRAY_COUNT(context[0]->freeQueueAndStack.threadStack),
                           sizeof(context[0]->freeQueueAndStack.threadStack), priority, 1) == 0)
        {
            return 0;
        }
    }
    else
    {
        if (OSCreateThread(&context[0]->decodeThread.thread, AudioDecoder, NULL,
                           context[0]->freeQueueAndStack.threadStack +
                               ARRAY_COUNT(context[0]->freeQueueAndStack.threadStack),
                           sizeof(context[0]->freeQueueAndStack.threadStack), priority, 1) == 0)
        {
            return 0;
        }
    }
    OSInitMessageQueue(&context[0]->freeQueueAndStack.queue, context[0]->messages.free,
                       ARRAY_COUNT(context[0]->messages.free));
    OSInitMessageQueue(&context[0]->decodedQueue, context[0]->messages.decoded,
                       ARRAY_COUNT(context[0]->messages.decoded));
    gAttractMovieAudioThreadActive = 1;
    return 1;
}

AttractMovieDecodeThread gAttractMovieAudioDecodeThread;
AttractMovieFreeQueueAndStack gAttractMovieFreeAudioQueueAndStack;
OSMessageQueue gAttractMovieDecodedAudioQueue;
AttractMovieAudioMessageStorage gAttractMovieAudioDecodeContext;
