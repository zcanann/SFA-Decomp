#include "main/audio_decode_thread.h"
#include "main/dll/FRONT/dll_3B.h"

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
                           context[0]->freeQueueAndStack.threadStack + 0x1000 / sizeof(u32), 0x1000, priority, 1) == 0)
        {
            return 0;
        }
    }
    else
    {
        if (OSCreateThread(&context[0]->decodeThread.thread, AudioDecoder, NULL,
                           context[0]->freeQueueAndStack.threadStack + 0x1000 / sizeof(u32), 0x1000, priority, 1) == 0)
        {
            return 0;
        }
    }
    OSInitMessageQueue(&context[0]->freeQueueAndStack.queue, context[0]->messages.free, 3);
    OSInitMessageQueue(&context[0]->decodedQueue, context[0]->messages.decoded, 3);
    gAttractMovieAudioThreadActive = 1;
    return 1;
}
