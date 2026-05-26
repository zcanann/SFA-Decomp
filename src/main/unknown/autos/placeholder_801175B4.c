#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_801175B4.h"
#include "dolphin/os.h"

extern void *AudioDecoderForOnMemory(void *);
extern void *AudioDecoder(void *);
extern int gAttractMovieAudioThreadActive;

typedef struct THPAudioDecodeContext {
    OSMessage freeAudioBuffers[3];
    OSMessage decodedAudioBuffers[3];
    OSMessageQueue freeQueue;
    OSMessageQueue decodedQueue;
    u8 pad58[0x1058 - 0x58];
    OSThread thread;
} THPAudioDecodeContext;

extern THPAudioDecodeContext lbl_803A4448;

/*
 * --INFO--
 *
 * Function: CreateAudioDecodeThread
 * EN v1.0 Address: 0x801175A4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801175B4
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
BOOL CreateAudioDecodeThread(OSPriority priority, void *param)
{
    THPAudioDecodeContext *context = &lbl_803A4448;

    if (param != NULL) {
        if (OSCreateThread(&context->thread, AudioDecoderForOnMemory, param,
                           &context->thread, 0x1000, priority, 1) == 0) {
            return 0;
        }
    } else {
        if (OSCreateThread(&context->thread, AudioDecoder, NULL,
                           &context->thread, 0x1000, priority, 1) == 0) {
            return 0;
        }
    }
    OSInitMessageQueue(&context->decodedQueue, context->decodedAudioBuffers, 3);
    OSInitMessageQueue(&context->freeQueue, context->freeAudioBuffers, 3);
    gAttractMovieAudioThreadActive = 1;
    return 1;
}
#pragma peephole reset
#pragma scheduling reset
