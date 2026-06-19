#include "main/audio_decode_thread.h"
#include "main/dll/FRONT/dll_3B.h"



extern int gAttractMovieAudioThreadActive;

typedef struct THPAudioDecodeContext
{
    OSMessage freeAudioBuffers[3];
    OSMessage decodedAudioBuffers[3];
    OSMessageQueue freeQueue;
    OSMessageQueue decodedQueue;
    u8 pad58[0x1058 - 0x58];
    OSThread thread;
} THPAudioDecodeContext;

extern THPAudioDecodeContext lbl_803A4448;

BOOL CreateAudioDecodeThread(OSPriority priority, void* param)
{
    THPAudioDecodeContext* context = &lbl_803A4448;

    if (param != NULL)
    {
        if (OSCreateThread(&context->thread, AudioDecoderForOnMemory, param,
                           &context->thread, 0x1000, priority, 1) == 0)
        {
            return 0;
        }
    }
    else
    {
        if (OSCreateThread(&context->thread, AudioDecoder, NULL,
                           &context->thread, 0x1000, priority, 1) == 0)
        {
            return 0;
        }
    }
    OSInitMessageQueue(&context->decodedQueue, context->decodedAudioBuffers, 3);
    OSInitMessageQueue(&context->freeQueue, context->freeAudioBuffers, 3);
    gAttractMovieAudioThreadActive = 1;
    return 1;
}
