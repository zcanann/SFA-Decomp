#ifndef MAIN_DLL_FRONT_DLL_3B_H_
#define MAIN_DLL_FRONT_DLL_3B_H_

#include "types.h"
#include "dolphin/os.h"
#include "main/dll/FRONT/attract_movie.h"
#include "main/dll/FRONT/title_menu.h"

extern s32 gAttractMovieAudioThreadActive;

typedef struct AttractMovieAudioMessageStorage
{
    OSMessage decoded[3];
    OSMessage free[3];
} AttractMovieAudioMessageStorage;

typedef struct AttractMovieFreeQueueAndStack
{
    OSMessageQueue queue;
    u32 threadStack[0x1000 / sizeof(u32)];
} AttractMovieFreeQueueAndStack;

typedef struct AttractMovieDecodeThread
{
    OSThread thread;
    u32 reserved[0x10 / sizeof(u32)];
} AttractMovieDecodeThread;

STATIC_ASSERT(sizeof(AttractMovieAudioMessageStorage) == 0x18);
STATIC_ASSERT(sizeof(AttractMovieFreeQueueAndStack) == 0x1020);
STATIC_ASSERT(sizeof(AttractMovieDecodeThread) == 0x320);

extern AttractMovieAudioMessageStorage gAttractMovieAudioDecodeContext;
extern OSMessageQueue gAttractMovieDecodedAudioQueue;
extern AttractMovieFreeQueueAndStack gAttractMovieFreeAudioQueueAndStack;
extern AttractMovieDecodeThread gAttractMovieAudioDecodeThread;

void TitleMenu_initialise(void);
void *PopDecodedAudioBuffer(int flags);
void PushFreeAudioBuffer(void *message);
void AudioDecodeThreadCancel(void);
void AudioDecodeThreadStart(void);
void AttractMovieAudio_InitQueuesPC(void);
void AttractMovieAudio_DecodeFramePC(u8 *audioFrame, s32 frameNumber);

#endif /* MAIN_DLL_FRONT_DLL_3B_H_ */
