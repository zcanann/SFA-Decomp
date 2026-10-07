/*
 * THPRead - attract-movie DVD reader thread and message queues.
 */
#include "main/thp_read.h"
#include "main/thp_player.h"
#include "dolphin/os/OSThread.h"
#include "dolphin/os/OSMessage.h"

#define THP_READ_STACK_SIZE 0x1000

OSMessageQueue gAttractMovieReadFreeQueue;
OSMessageQueue gAttractMovieReadDvdQueue;
OSMessageQueue gAttractMovieReadAudioDecodedQueue;
OSMessage gAttractMovieReadFreeMessages[ATTRACT_MOVIE_READ_BUFFER_COUNT];
OSMessage gAttractMovieReadDvdMessages[ATTRACT_MOVIE_READ_BUFFER_COUNT];
OSMessage gAttractMovieReadAudioDecodedMessages[ATTRACT_MOVIE_READ_BUFFER_COUNT];
OSThread gAttractMovieReadThread;
char gAttractMovieReadThreadStack[THP_READ_STACK_SIZE];

s32 gAttractMovieReadThreadCreated;

static void* THPRead_Reader(void* unused);

BOOL CreateReadThread(OSPriority priority) {
    char* stackTop = gAttractMovieReadThreadStack + sizeof(gAttractMovieReadThreadStack);

    if (!OSCreateThread(&gAttractMovieReadThread, THPRead_Reader, NULL, stackTop, THP_READ_STACK_SIZE, priority, 1)) {
        return 0;
    }

    OSInitMessageQueue(&gAttractMovieReadFreeQueue, gAttractMovieReadFreeMessages, ATTRACT_MOVIE_READ_BUFFER_COUNT);
    OSInitMessageQueue(&gAttractMovieReadDvdQueue, gAttractMovieReadDvdMessages, ATTRACT_MOVIE_READ_BUFFER_COUNT);
    OSInitMessageQueue(&gAttractMovieReadAudioDecodedQueue, gAttractMovieReadAudioDecodedMessages,
                       ATTRACT_MOVIE_READ_BUFFER_COUNT);
    gAttractMovieReadThreadCreated = 1;
    return 1;
}

void ReadThreadStart(void) {
    if (gAttractMovieReadThreadCreated != 0) {
        OSResumeThread(&gAttractMovieReadThread);
    }
}

void ReadThreadCancel(void) {
    if (gAttractMovieReadThreadCreated != 0) {
        OSCancelThread(&gAttractMovieReadThread);
        gAttractMovieReadThreadCreated = 0;
    }
}

static void* THPRead_Reader(void* unused) {
    AttractMovieReadBuffer* readBuffer;
    u32 readOffset;
    u32 frameSize;
    int frameNumber;

    frameNumber = 0;
    readOffset = gAttractMoviePlayer.initOffset;
    frameSize = gAttractMoviePlayer.initReadSize;

    while (1) {
        OSMessage received;
        s32 readResult;

        OSReceiveMessage(&gAttractMovieReadFreeQueue, &received, OS_MESSAGE_BLOCK);
        readBuffer = (AttractMovieReadBuffer*)received;

        readResult = DVDReadPrio(&gAttractMoviePlayer.fileInfo, readBuffer->ptr, frameSize, readOffset, 2);
        if (readResult != (s32)frameSize) {
            if (readResult == -1) {
                gAttractMoviePlayer.dvdError = -1;
            }
            if (frameNumber == 0) {
                PrepareReady(0);
            }
            OSSuspendThread(&gAttractMovieReadThread);
        }

        readBuffer->frameNumber = frameNumber;
        OSSendMessage(&gAttractMovieReadDvdQueue, (OSMessage)readBuffer, OS_MESSAGE_BLOCK);

        readOffset += frameSize;
        frameSize = *(u32*)readBuffer->ptr;

        {
            u32 frameCount = gAttractMoviePlayer.header.mNumFrames;
            u32 initialFrame = gAttractMoviePlayer.initReadFrame;
            u32 movieFrame = (frameNumber + initialFrame) % frameCount;
            if (movieFrame == frameCount - 1) {
                if (gAttractMoviePlayer.playFlags & 1) {
                    readOffset = gAttractMoviePlayer.header.mMovieDataOffsets;
                } else {
                    OSSuspendThread(&gAttractMovieReadThread);
                }
            }
        }
        frameNumber++;
    }
}

AttractMovieReadBuffer* PopReadedBuffer(void) {
    AttractMovieReadBuffer* buffer;
    OSReceiveMessage(&gAttractMovieReadDvdQueue, &buffer, OS_MESSAGE_BLOCK);
    return buffer;
}

void PushFreeReadBuffer(AttractMovieReadBuffer* buffer) {
    OSSendMessage(&gAttractMovieReadFreeQueue, buffer, OS_MESSAGE_BLOCK);
}

AttractMovieReadBuffer* PopReadedBuffer2(void) {
    AttractMovieReadBuffer* buffer;
    OSReceiveMessage(&gAttractMovieReadAudioDecodedQueue, &buffer, OS_MESSAGE_BLOCK);
    return buffer;
}

void PushReadedBuffer2(AttractMovieReadBuffer* buffer) {
    OSSendMessage(&gAttractMovieReadAudioDecodedQueue, buffer, OS_MESSAGE_BLOCK);
}
