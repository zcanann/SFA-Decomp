#include "main/audio_decode_thread.h"
#include "main/dll/FRONT/dll_3B.h"

typedef struct AttractMovieAudioDecodeContext
{
    OSMessage decodedAudioBuffers[3];
    OSMessage freeAudioBuffers[3];
    OSMessageQueue decodedQueue;
    OSMessageQueue freeQueue;
    u8 stack[0x1000];
    OSThread thread;
} AttractMovieAudioDecodeContext;

STATIC_ASSERT(offsetof(AttractMovieAudioDecodeContext, decodedAudioBuffers) == 0x0);
STATIC_ASSERT(offsetof(AttractMovieAudioDecodeContext, freeAudioBuffers) == 0xc);
STATIC_ASSERT(offsetof(AttractMovieAudioDecodeContext, decodedQueue) == 0x18);
STATIC_ASSERT(offsetof(AttractMovieAudioDecodeContext, freeQueue) == 0x38);
STATIC_ASSERT(offsetof(AttractMovieAudioDecodeContext, stack) == 0x58);
STATIC_ASSERT(offsetof(AttractMovieAudioDecodeContext, thread) == 0x1058);

extern AttractMovieAudioDecodeContext gAttractMovieAudioDecodeContext;

BOOL CreateAudioDecodeThread(OSPriority priority, void* param)
{
    AttractMovieAudioDecodeContext* context[1];
    context[0] = &gAttractMovieAudioDecodeContext;

    if (param != NULL)
    {
        if (OSCreateThread(&context[0]->thread, AudioDecoderForOnMemory, param,
                           context[0]->stack + sizeof(context[0]->stack), 0x1000, priority, 1) == 0)
        {
            return 0;
        }
    }
    else
    {
        if (OSCreateThread(&context[0]->thread, AudioDecoder, NULL,
                           context[0]->stack + sizeof(context[0]->stack), 0x1000, priority, 1) == 0)
        {
            return 0;
        }
    }
    OSInitMessageQueue(&context[0]->freeQueue, context[0]->freeAudioBuffers, 3);
    OSInitMessageQueue(&context[0]->decodedQueue, context[0]->decodedAudioBuffers, 3);
    gAttractMovieAudioThreadActive = 1;
    return 1;
}
