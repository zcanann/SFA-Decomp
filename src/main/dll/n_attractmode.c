#include "dolphin/os/OSReport.h"
#include "dolphin/os.h"
#include "dolphin/vi.h"
#include "main/attract_movie_api.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/dll/FRONT/dll_44.h"
#include "main/dll/baddie/dll_003C_TumbleweedBush.h"
#include "main/dll/dll_02C0_front_api.h"
#include "main/mm.h"

extern s32 gAttractMovieState;
extern u8 gAttractMoviePreparePending;
extern void* gAttractMovieBuffer0;
extern void* gAttractMovieBuffer1;
extern void* gAttractMovieBuffer2;
extern void* gAttractMovieBuffer3;
extern void* gAttractMovieOptionalBuffer;
extern void* gAttractMovieWorkBuffer;
extern void* gAttractMovieScratchBuffer;
extern NAttractModeMovieDims gAttractMovieDims;
extern int gAttractMovieOffsetX;
extern int gAttractMovieOffsetY;
extern u8 gAttractMovieRetraceCountdown;
extern s32 gAttractMovieIdleFrameCount;
extern u8 gTitleMenuSelection;
extern u16* gRenderModeObj;
extern char sNAttractModeStringBlock[];

extern bool prepareAttractMode();
extern void printHeapStats(int mode);

#define NATTRACTMODE_MOVIE_PATH_OFFSET      0x154
#define NATTRACTMODE_MALLOC_FAILED_OFFSET   0x160
#define NATTRACTMODE_RESTRUCT_MOVIE_OFFSET  0x18C
#define NATTRACTMODE_SOURCE_FILE_OFFSET     0x1B4
#define NATTRACTMODE_FAIL_TO_PREPARE_OFFSET 0x1C4

void n_attractmode_releaseMovieBuffers(void)
{
    int freeDelay;

    if (gAttractMovieState == NATTRACTMODE_MOVIE_STATE_PREPARED)
    {
        THPPlayerStop();
        AttractMovie_CloseFile();
        AttractMovieAudio_Shutdown();
        freeDelay = mmSetFreeDelay(0);
        if (gAttractMovieBuffer0 != 0)
        {
            mm_free(gAttractMovieBuffer0);
            gAttractMovieBuffer0 = 0;
        }
        if (gAttractMovieBuffer1 != 0)
        {
            mm_free(gAttractMovieBuffer1);
            gAttractMovieBuffer1 = 0;
        }
        if (gAttractMovieBuffer2 != 0)
        {
            mm_free(gAttractMovieBuffer2);
            gAttractMovieBuffer2 = 0;
        }
        if (gAttractMovieBuffer3 != 0)
        {
            mm_free(gAttractMovieBuffer3);
            gAttractMovieBuffer3 = 0;
        }
        if (gAttractMovieOptionalBuffer != 0)
        {
            mm_free(gAttractMovieOptionalBuffer);
            gAttractMovieOptionalBuffer = 0;
        }
        if (gAttractMovieWorkBuffer != 0)
        {
            mm_free(gAttractMovieWorkBuffer);
            gAttractMovieWorkBuffer = 0;
        }
        if (gAttractMovieScratchBuffer != 0)
        {
            mm_free(gAttractMovieScratchBuffer);
            gAttractMovieScratchBuffer = 0;
        }
        mmSetFreeDelay(freeDelay);
        gAttractMovieState = NATTRACTMODE_MOVIE_STATE_RELEASED;
        gAttractMoviePreparePending = NATTRACTMODE_MOVIE_BUSY;
    }
    return;
}

void n_attractmode_prepareMovie(void)
{
    char* attractModeStrings;
    int ok;
    int freeDelay;
    int movieBuffer1Size;
    int movieBuffer2Size;
    int movieBuffer3Size;
    u32 optionalBufferSize;
    int workBufferSize;
    u32 movieBuffer0Size[3];

    attractModeStrings = sNAttractModeStringBlock;
    gAttractMoviePreparePending = NATTRACTMODE_MOVIE_BUSY;
    ok = AttractMovieAudio_Init(NATTRACTMODE_MOVIE_SETUP_ID);
    if (ok != 0)
    {
        ok = movieLoad(attractModeStrings + NATTRACTMODE_MOVIE_PATH_OFFSET, NATTRACTMODE_MOVIE_START_FRAME_DEFAULT);
        if (ok == 0)
        {
            AttractMovieAudio_Shutdown();
        }
        else
        {
            THPPlayerGetVideoInfo(&gAttractMovieDims);
            gAttractMovieOffsetX = ((u32)gRenderModeObj[2] - gAttractMovieDims.width) >> 1;
            gAttractMovieOffsetY = ((u32)gRenderModeObj[3] - gAttractMovieDims.height) >> 1;
            AttractMovie_GetBufferSizes(movieBuffer0Size, &movieBuffer1Size, &movieBuffer2Size, &movieBuffer3Size,
                                        &optionalBufferSize, &workBufferSize);
            gAttractMovieBuffer0 = mmAlloc(movieBuffer0Size[0], NATTRACTMODE_MOVIE_HEAP, 0);
            gAttractMovieBuffer1 = mmAlloc(movieBuffer1Size, NATTRACTMODE_MOVIE_HEAP, 0);
            gAttractMovieBuffer2 = mmAlloc(movieBuffer2Size, NATTRACTMODE_MOVIE_HEAP, 0);
            gAttractMovieBuffer3 = mmAlloc(movieBuffer3Size, NATTRACTMODE_MOVIE_HEAP, 0);
            if (optionalBufferSize != NATTRACTMODE_OPTIONAL_BUFFER_SIZE_NONE)
            {
                gAttractMovieOptionalBuffer = mmAlloc(optionalBufferSize, NATTRACTMODE_MOVIE_HEAP, 0);
            }
            else
            {
                gAttractMovieOptionalBuffer = 0;
            }
            gAttractMovieWorkBuffer = mmAlloc(workBufferSize, NATTRACTMODE_MOVIE_HEAP, 0);
            gAttractMovieScratchBuffer = mmAlloc(NATTRACTMODE_WORK_BUFFER_SIZE, NATTRACTMODE_MOVIE_HEAP, 0);
            if (((((gAttractMovieBuffer0 == 0) || (gAttractMovieBuffer1 == 0)) || (gAttractMovieBuffer2 == 0)) ||
                 ((gAttractMovieBuffer3 == 0 || ((gAttractMovieOptionalBuffer == 0 &&
                                                  (optionalBufferSize != NATTRACTMODE_OPTIONAL_BUFFER_SIZE_NONE)))))) ||
                ((gAttractMovieWorkBuffer == 0 || (gAttractMovieScratchBuffer == 0))))
            {
                AttractMovieAudio_Shutdown();
                freeDelay = mmSetFreeDelay(0);
                if (gAttractMovieBuffer0 != 0)
                {
                    mm_free(gAttractMovieBuffer0);
                    gAttractMovieBuffer0 = 0;
                }
                if (gAttractMovieBuffer1 != 0)
                {
                    mm_free(gAttractMovieBuffer1);
                    gAttractMovieBuffer1 = 0;
                }
                if (gAttractMovieBuffer2 != 0)
                {
                    mm_free(gAttractMovieBuffer2);
                    gAttractMovieBuffer2 = 0;
                }
                if (gAttractMovieBuffer3 != 0)
                {
                    mm_free(gAttractMovieBuffer3);
                    gAttractMovieBuffer3 = 0;
                }
                if (gAttractMovieOptionalBuffer != 0)
                {
                    mm_free(gAttractMovieOptionalBuffer);
                    gAttractMovieOptionalBuffer = 0;
                }
                if (gAttractMovieWorkBuffer != 0)
                {
                    mm_free(gAttractMovieWorkBuffer);
                    gAttractMovieWorkBuffer = 0;
                }
                if (gAttractMovieScratchBuffer != 0)
                {
                    mm_free(gAttractMovieScratchBuffer);
                    gAttractMovieScratchBuffer = 0;
                }
                mmSetFreeDelay(freeDelay);
                OSReport(attractModeStrings + NATTRACTMODE_MALLOC_FAILED_OFFSET);
                printHeapStats(1);
                defragMemory(0);
                OSReport(attractModeStrings + NATTRACTMODE_RESTRUCT_MOVIE_OFFSET);
                printHeapStats(1);
            }
            else
            {
                gAttractMoviePreparePending = NATTRACTMODE_MOVIE_READY;
                DCInvalidateRange(gAttractMovieBuffer0, movieBuffer0Size[0]);
                DCInvalidateRange(gAttractMovieBuffer1, movieBuffer1Size);
                DCInvalidateRange(gAttractMovieBuffer2, movieBuffer2Size);
                DCInvalidateRange(gAttractMovieBuffer3, movieBuffer3Size);
                if (gAttractMovieOptionalBuffer != 0)
                {
                    DCInvalidateRange(gAttractMovieOptionalBuffer, optionalBufferSize);
                }
                DCInvalidateRange(gAttractMovieWorkBuffer, workBufferSize);
                DCInvalidateRange(gAttractMovieScratchBuffer, NATTRACTMODE_WORK_BUFFER_SIZE);
                AttractMovie_AssignBuffers(gAttractMovieBuffer0, gAttractMovieBuffer1, gAttractMovieBuffer2,
                                           gAttractMovieBuffer3, gAttractMovieOptionalBuffer, gAttractMovieWorkBuffer);
                ok = prepareAttractMode(0, 1);
                if (ok == 0)
                {
                    OSPanic(attractModeStrings + NATTRACTMODE_SOURCE_FILE_OFFSET, NATTRACTMODE_PREPARE_FAIL_LINE,
                            attractModeStrings + NATTRACTMODE_FAIL_TO_PREPARE_OFFSET);
                }
                THPPlayerPlay();
                gAttractMovieState = NATTRACTMODE_MOVIE_STATE_PREPARED;
                VIWaitForRetrace();
                gAttractMovieRetraceCountdown = NATTRACTMODE_MOVIE_RETRACE_COUNTDOWN;
                gAttractMovieIdleFrameCount = 0;
                if ((int)gTitleMenuSelection == TITLE_MENU_ATTRACT_MOVIE_STATE)
                {
                    Movie_SetVolumeFade(NATTRACTMODE_MOVIE_VOLUME_TITLE, NATTRACTMODE_MOVIE_VOLUME_FADE_IMMEDIATE);
                }
                else
                {
                    Movie_SetVolumeFade(NATTRACTMODE_MOVIE_VOLUME_MUTED, NATTRACTMODE_MOVIE_VOLUME_FADE_IMMEDIATE);
                }
            }
        }
    }
    return;
}
