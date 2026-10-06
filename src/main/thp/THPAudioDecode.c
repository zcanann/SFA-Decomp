/* THP audio decoding and its buffer queues. */
#include "main/audio_decode_thread.h"
#include "main/thp_read.h"
#include "main/thp_player.h"
#include "dolphin/os/OSMessage.h"
#include "dolphin/thp/THPAudio.h"

#define THP_AUDIO_STACK_SIZE   0x1000
#define THP_AUDIO_BUFFER_COUNT 3
#define THP_FRAME_COMP_AUDIO   1
#define THP_FRAME_HEADER_SIZE  8

OSThread gAttractMovieAudioDecodeThread;
u8 gAttractMovieAudioDecodeThreadStack[THP_AUDIO_STACK_SIZE];
OSMessageQueue gAttractMovieFreeAudioQueue;
OSMessageQueue gAttractMovieDecodedAudioQueue;
OSMessage gAttractMovieAudioFreeMessages[THP_AUDIO_BUFFER_COUNT];
OSMessage gAttractMovieAudioDecodedMessages[THP_AUDIO_BUFFER_COUNT];
s32 gAttractMovieAudioThreadActive;

static void* AudioDecoder(void* param);
static void* AudioDecoderForOnMemory(void* param);
static void AttractMovieAudio_Decode(AttractMovieReadBuffer* readBufferArg);

BOOL CreateAudioDecodeThread(OSPriority priority, void* param) {

    if (param != NULL) {
        if (OSCreateThread(&gAttractMovieAudioDecodeThread, AudioDecoderForOnMemory, param,
                           gAttractMovieAudioDecodeThreadStack + ARRAY_COUNT(gAttractMovieAudioDecodeThreadStack),
                           sizeof(gAttractMovieAudioDecodeThreadStack), priority, 1) == 0) {
            return 0;
        }
    } else {
        if (OSCreateThread(&gAttractMovieAudioDecodeThread, AudioDecoder, NULL,
                           gAttractMovieAudioDecodeThreadStack + ARRAY_COUNT(gAttractMovieAudioDecodeThreadStack),
                           sizeof(gAttractMovieAudioDecodeThreadStack), priority, 1) == 0) {
            return 0;
        }
    }
    OSInitMessageQueue(&gAttractMovieFreeAudioQueue, gAttractMovieAudioFreeMessages,
                       ARRAY_COUNT(gAttractMovieAudioFreeMessages));
    OSInitMessageQueue(&gAttractMovieDecodedAudioQueue, gAttractMovieAudioDecodedMessages,
                       ARRAY_COUNT(gAttractMovieAudioDecodedMessages));
    gAttractMovieAudioThreadActive = 1;
    return 1;
}

void AudioDecodeThreadStart(void) {
    if (gAttractMovieAudioThreadActive != 0) {
        OSResumeThread(&gAttractMovieAudioDecodeThread);
    }
}

void AudioDecodeThreadCancel(void) {
    if (gAttractMovieAudioThreadActive != 0) {
        OSCancelThread(&gAttractMovieAudioDecodeThread);
        gAttractMovieAudioThreadActive = 0;
    }
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

static void* AudioDecoderForOnMemory(void* param) {
    register AttractMoviePlayer* player;
    int stride;
    u32 framesPerGroup;
    u32 frameInGroup;
    register int frame;
    AttractMovieReadBuffer readBuffer;

    player = &gAttractMoviePlayer;
    stride = player->initReadSize;
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
                readBuffer.ptr = player->movieData;
            } else {
                OSSuspendThread(&gAttractMovieAudioDecodeThread);
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

static inline AttractMovieAudioBuffer* PopFreeAudioBuffer(void) {
    AttractMovieAudioBuffer* buffer;
    OSReceiveMessage(&gAttractMovieFreeAudioQueue, &buffer, OS_MESSAGE_BLOCK);
    return buffer;
}

static void AttractMovieAudio_Decode(AttractMovieReadBuffer* readBufferArg) {
    u32* audioFrameSizes;
    AttractMovieReadBuffer* readBuffer;
    AttractMovieAudioBuffer* audioBuffer;
    u8* audioFrame;
    u32 track;

    readBuffer = readBufferArg;
    audioFrameSizes = (u32*)(readBuffer->ptr + THP_FRAME_HEADER_SIZE);
    audioFrame = readBuffer->ptr + (gAttractMoviePlayer.compInfo.mNumComponents * sizeof(u32)) + THP_FRAME_HEADER_SIZE;
    audioBuffer = PopFreeAudioBuffer();
    for (track = 0; track < gAttractMoviePlayer.compInfo.mNumComponents; track++) {
        switch (gAttractMoviePlayer.compInfo.mFrameComp[track]) {
        case THP_FRAME_COMP_AUDIO:
            audioBuffer->validSample = THPAudioDecode(audioBuffer->buffer, audioFrame, 0);
            audioBuffer->curPtr = audioBuffer->buffer;
            audioBuffer->frameNumber = readBuffer->frameNumber;
            OSSendMessage(&gAttractMovieDecodedAudioQueue, audioBuffer, OS_MESSAGE_BLOCK);
            break;
        }
        audioFrame += *audioFrameSizes;
        audioFrameSizes++;
    }
}

void PushFreeAudioBuffer(void* message) {
    OSSendMessage(&gAttractMovieFreeAudioQueue, message, OS_MESSAGE_NOBLOCK);
}

void* PopDecodedAudioBuffer(int flags) {
    void* message;

    if (OSReceiveMessage(&gAttractMovieDecodedAudioQueue, &message, flags) == 1) {
        return message;
    }
    return NULL;
}
