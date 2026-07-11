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
    THPAudioDecodeContext* context[1];
    context[0] = &lbl_803A4448;

    if (param != NULL)
    {
        if (OSCreateThread(&context[0]->thread, AudioDecoderForOnMemory, param, &context[0]->thread, 0x1000, priority, 1) ==
            0)
        {
            return 0;
        }
    }
    else
    {
        if (OSCreateThread(&context[0]->thread, AudioDecoder, NULL, &context[0]->thread, 0x1000, priority, 1) == 0)
        {
            return 0;
        }
    }
    OSInitMessageQueue(&context[0]->decodedQueue, context[0]->decodedAudioBuffers, 3);
    OSInitMessageQueue(&context[0]->freeQueue, context[0]->freeAudioBuffers, 3);
    gAttractMovieAudioThreadActive = 1;
    return 1;
}
