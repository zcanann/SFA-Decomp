/*
 * THPRead - attract-movie DVD reader thread and message queues.
 */
#include "main/thp_read.h"
#include "main/dll/FRONT/attract_movie.h"
#include "dolphin/os/OSThread.h"
#include "dolphin/thp/THPPlayer.h"

#define THP_READ_STACK_SIZE 0x1000

/* Layout view of the separate globals used by the retail shared base. */
typedef struct AttractMovieReadThreadLayout {
    char stack[THP_READ_STACK_SIZE];
    OSThread thread;
    OSMessage audioDecodedMessages[ATTRACT_MOVIE_READ_BUFFER_COUNT];
    OSMessage readMessages[ATTRACT_MOVIE_READ_BUFFER_COUNT];
    OSMessage freeMessages[ATTRACT_MOVIE_READ_BUFFER_COUNT];
    OSMessageQueue audioDecodedQueue;
    OSMessageQueue readQueue;
    OSMessageQueue freeQueue;
} AttractMovieReadThreadLayout;

STATIC_ASSERT(offsetof(AttractMovieReadThreadLayout, thread) == 0x1000);
STATIC_ASSERT(offsetof(AttractMovieReadThreadLayout, audioDecodedMessages) == 0x1310);
STATIC_ASSERT(offsetof(AttractMovieReadThreadLayout, readMessages) == 0x1338);
STATIC_ASSERT(offsetof(AttractMovieReadThreadLayout, freeMessages) == 0x1360);
STATIC_ASSERT(offsetof(AttractMovieReadThreadLayout, audioDecodedQueue) == 0x1388);
STATIC_ASSERT(offsetof(AttractMovieReadThreadLayout, readQueue) == 0x13A8);
STATIC_ASSERT(offsetof(AttractMovieReadThreadLayout, freeQueue) == 0x13C8);
STATIC_ASSERT(sizeof(AttractMovieReadThreadLayout) == 0x13E8);

char gPicMenuReadThreadStack[THP_READ_STACK_SIZE];
OSThread gPicMenuReadThread;

extern OSMessageQueue gPicMenuReadedBuffer2Queue;
extern OSMessageQueue gPicMenuReadedBufferQueue;
extern OSMessageQueue gPicMenuFreeReadBufferQueue;

s32 gPicMenuReadThreadCreated;

void PushReadedBuffer2(AttractMovieReadBuffer* buffer) {
    OSSendMessage(&gPicMenuReadedBuffer2Queue, buffer, OS_MESSAGE_BLOCK);
}

AttractMovieReadBuffer* PopReadedBuffer2(void) {
    AttractMovieReadBuffer* buffer;
    OSReceiveMessage(&gPicMenuReadedBuffer2Queue, &buffer, OS_MESSAGE_BLOCK);
    return buffer;
}

void PushFreeReadBuffer(AttractMovieReadBuffer* buffer) {
    OSSendMessage(&gPicMenuFreeReadBufferQueue, buffer, OS_MESSAGE_BLOCK);
}

AttractMovieReadBuffer* PopReadedBuffer(void) {
    AttractMovieReadBuffer* buffer;
    OSReceiveMessage(&gPicMenuReadedBufferQueue, &buffer, OS_MESSAGE_BLOCK);
    return buffer;
}

static void* THPRead_Reader(void* unused) {
    AttractMovieReadBuffer* readBuffer;
    u32 readOffset;
    u32 frameSize;
    char* base;
    int frameNumber;

    base = gPicMenuReadThreadStack;
    frameNumber = 0;
    readOffset = gAttractMoviePlayer.initOffset;
    frameSize = gAttractMoviePlayer.initReadSize;

    while (1) {
        OSMessage received;
        s32 readResult;

        OSReceiveMessage((OSMessageQueue*)(base + offsetof(AttractMovieReadThreadLayout, freeQueue)), &received,
                         OS_MESSAGE_BLOCK);
        readBuffer = (AttractMovieReadBuffer*)received;

        readResult = DVDReadPrio(&gAttractMoviePlayer.fileInfo, readBuffer->ptr, frameSize, readOffset, 2);
        if (readResult != (s32)frameSize) {
            if (readResult == -1) {
                gAttractMoviePlayer.dvdError = -1;
            }
            if (frameNumber == 0) {
                PrepareReady(0);
            }
            OSSuspendThread((OSThread*)(base + offsetof(AttractMovieReadThreadLayout, thread)));
        }

        readBuffer->frameNumber = frameNumber;
        OSSendMessage((OSMessageQueue*)(base + offsetof(AttractMovieReadThreadLayout, readQueue)),
                      (OSMessage)readBuffer, OS_MESSAGE_BLOCK);

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
                    OSSuspendThread((OSThread*)(base + offsetof(AttractMovieReadThreadLayout, thread)));
                }
            }
        }
        frameNumber++;
    }
}

void ReadThreadCancel(void) {
    if (gPicMenuReadThreadCreated != 0) {
        OSCancelThread(&gPicMenuReadThread);
        gPicMenuReadThreadCreated = 0;
    }
}

void ReadThreadStart(void) {
    if (gPicMenuReadThreadCreated != 0) {
        OSResumeThread(&gPicMenuReadThread);
    }
}

BOOL CreateReadThread(OSPriority priority) {
    char* base = gPicMenuReadThreadStack;
    char* stackTop = base + THP_READ_STACK_SIZE;

    if (!OSCreateThread((OSThread*)(base + offsetof(AttractMovieReadThreadLayout, thread)), THPRead_Reader, NULL,
                        stackTop, THP_READ_STACK_SIZE, priority, 1)) {
        return 0;
    }

    OSInitMessageQueue((OSMessageQueue*)(base + offsetof(AttractMovieReadThreadLayout, freeQueue)),
                       (void*)(base + offsetof(AttractMovieReadThreadLayout, freeMessages)),
                       ATTRACT_MOVIE_READ_BUFFER_COUNT);
    OSInitMessageQueue((OSMessageQueue*)(base + offsetof(AttractMovieReadThreadLayout, readQueue)),
                       (void*)(base + offsetof(AttractMovieReadThreadLayout, readMessages)),
                       ATTRACT_MOVIE_READ_BUFFER_COUNT);
    OSInitMessageQueue((OSMessageQueue*)(base + offsetof(AttractMovieReadThreadLayout, audioDecodedQueue)),
                       (void*)(base + offsetof(AttractMovieReadThreadLayout, audioDecodedMessages)),
                       ATTRACT_MOVIE_READ_BUFFER_COUNT);
    gPicMenuReadThreadCreated = 1;
    return 1;
}

OSMessageQueue gPicMenuFreeReadBufferQueue;
OSMessageQueue gPicMenuReadedBufferQueue;
OSMessageQueue gPicMenuReadedBuffer2Queue;
OSMessage gPicMenuFreeReadBufferMessages[ATTRACT_MOVIE_READ_BUFFER_COUNT];
OSMessage gPicMenuReadedBufferMessages[ATTRACT_MOVIE_READ_BUFFER_COUNT];
OSMessage gPicMenuReadedBuffer2Messages[ATTRACT_MOVIE_READ_BUFFER_COUNT];
