#include "main/dll/FRONT/dll_39.h"
#include "main/dll/FRONT/dll_44.h"
#include "main/dll/FRONT/picmenu.h"
#include "main/camera_interface.h"
#include "main/screen_transition.h"

extern void Movie_SetVolumeFade(int volume, int fadeFrames);
extern bool prepareAttractMode();
extern void fn_8001404C(int param_1);
extern void loadUiDll(int id);
extern void gameTextSetDrawFunc(void* callback);
extern void GameBit_Set(int eventId, int value);
extern u8 shouldShowCredits(u8 * obj);
extern void creditsStart_(void);
extern void titleScreenShowCopyright(u8 param_1);
extern void gameTextBoxFn_80134d40(int param_1, int param_2, int param_3);
extern void titleScreenPositionElements(f32 param_1, f32 param_2);
extern void titleScreenTextDrawFunc(void);

extern char sNAttractModeStringBlock[];
static char sNRarewareReportTag[] = "n_rareware\n";

extern void* mmAlloc(int size, int heap, int flags);
extern uint mmSetFreeDelay(uint delay);
extern void mm_free(void* ptr);
extern void printHeapStats(int param_1);
extern void defragMemory(int param_1);
extern void OSReport(const char* fmt, ...);
extern void VIWaitForRetrace(void);

extern u8 framesThisStep;
extern f32 timeDelta;
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern TitleMenuControl* gTitleMenuLinkInterface;
extern int lbl_803DD5F8;
extern s8 lbl_803DD5FC;
extern f32 lbl_803DD600;
extern f32 lbl_803DD604;
extern u8 lbl_803DD608;
extern s8 lbl_803DD609;
extern u8 lbl_803DD60A;
extern u8 gTitleMenuSelectionFade;
extern s32 gAttractMovieState;
extern u8 gTitleMenuSelection;
extern u8 gAttractMoviePreparePending;
extern void* gAttractMovieScratchBuffer;
extern void* gAttractMovieWorkBuffer;
extern void* gAttractMovieOptionalBuffer;
extern void* gAttractMovieBuffer3;
extern void* gAttractMovieBuffer2;
extern void* gAttractMovieBuffer1;
extern void* gAttractMovieBuffer0;
extern NAttractModeMovieDims gAttractMovieDims;
extern int gAttractMovieOffsetY;
extern int gAttractMovieOffsetX;
extern u8 gAttractMovieRetraceCountdown;
extern u8 gAttractMoviePlaybackEnabled;
extern s32 gAttractMovieIdleFrameCount;
extern u16* gRenderModeObj;
extern f32 lbl_803E1D10;
extern f32 lbl_803E1D14;
extern f32 lbl_803E1D18;

#define NATTRACTMODE_MOVIE_PATH_OFFSET 0x154
#define NATTRACTMODE_MALLOC_FAILED_OFFSET 0x160
#define NATTRACTMODE_RESTRUCT_MOVIE_OFFSET 0x18C
#define NATTRACTMODE_SOURCE_FILE_OFFSET 0x1B4
#define NATTRACTMODE_FAIL_TO_PREPARE_OFFSET 0x1C4
/*
 * --INFO--
 *
 * Function: n_rareware_frameStart
 * EN v1.0 Address: 0x80115FBC
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80115FF0
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int n_rareware_frameStart(void)
{
    int frameStep;

    frameStep = framesThisStep;
    OSReport(sNRarewareReportTag);
    if (frameStep > 3)
    {
        frameStep = 3;
    }
    if ((s8)lbl_803DD609 > 0)
    {
        lbl_803DD609 = (s8)(lbl_803DD609 - frameStep);
    }
    if ((s8)lbl_803DD608 != 0)
    {
        GameBit_Set(0x44f, 0);
        loadUiDll(4);
    }
    lbl_803DD5F8 += framesThisStep;
    if (lbl_803DD5F8 > 0x26c)
    {
        lbl_803DD60A = 1;
    }
    if ((s8)lbl_803DD60A != 0)
    {
        (*gScreenTransitionInterface)->start(0x1e, 1);
        lbl_803DD609 = 0x2d;
        lbl_803DD608 = 1;
    }
    if (lbl_803DD5FC > 0)
    {
        lbl_803DD604 -= timeDelta;
    }
    if (lbl_803DD5FC > 2)
    {
        lbl_803DD600 -= timeDelta;
    }
    return 0;
}

void n_rareware_release(void)
{
}

/*
 * --INFO--
 *
 * Function: n_rareware_initialise
 * EN v1.0 Address: 0x801160E0
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void n_rareware_initialise(void)
{
    fn_8001404C(0);
    lbl_803DD5F8 = 0;
    lbl_803DD5FC = 0;
    lbl_803DD60A = 0;
    lbl_803DD609 = 0;
    lbl_803DD608 = 0;
}

/*
 * --INFO--
 *
 * Function: n_attractmode_releaseMovieBuffers
 * EN v1.0 Address: 0x8011611C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x801163B8
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

/*
 * --INFO--
 *
 * Function: n_attractmode_prepareMovie
 * EN v1.0 Address: 0x80116224
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x801164C0
 * EN v1.1 Size: 920b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void n_attractmode_prepareMovie(void)
{
    char* attractModeStrings;
    int ok;
    int freeDelay;
    int movieBuffer1Size;
    int movieBuffer2Size;
    int movieBuffer3Size;
    uint optionalBufferSize;
    int workBufferSize;
    uint movieBuffer0Size[3];

    attractModeStrings = sNAttractModeStringBlock;
    gAttractMoviePreparePending = NATTRACTMODE_MOVIE_BUSY;
    ok = AttractMovieAudio_Init(NATTRACTMODE_MOVIE_SETUP_ID);
    if (ok != 0)
    {
        ok = movieLoad(attractModeStrings + NATTRACTMODE_MOVIE_PATH_OFFSET,
                       NATTRACTMODE_MOVIE_START_FRAME_DEFAULT);
        if (ok == 0)
        {
            AttractMovieAudio_Shutdown();
        }
        else
        {
            THPPlayerGetVideoInfo(&gAttractMovieDims);
            gAttractMovieOffsetX = ((uint)gRenderModeObj[2] - gAttractMovieDims.width) >> 1;
            gAttractMovieOffsetY = ((uint)gRenderModeObj[3] - gAttractMovieDims.height) >> 1;
            AttractMovie_GetBufferSizes(movieBuffer0Size, &movieBuffer1Size, &movieBuffer2Size,
                                        &movieBuffer3Size, &optionalBufferSize, &workBufferSize);
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
            if (((((gAttractMovieBuffer0 == 0) || (gAttractMovieBuffer1 == 0)) ||
                    (gAttractMovieBuffer2 == 0)) || ((gAttractMovieBuffer3 == 0 ||
                    ((gAttractMovieOptionalBuffer == 0 &&
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
                AttractMovie_AssignBuffers(gAttractMovieBuffer0, gAttractMovieBuffer1,
                                           gAttractMovieBuffer2, gAttractMovieBuffer3,
                                           gAttractMovieOptionalBuffer, gAttractMovieWorkBuffer);
                ok = prepareAttractMode(0, 1);
                if (ok == 0)
                {
                    OSPanic(attractModeStrings + NATTRACTMODE_SOURCE_FILE_OFFSET,
                            NATTRACTMODE_PREPARE_FAIL_LINE,
                            attractModeStrings + NATTRACTMODE_FAIL_TO_PREPARE_OFFSET);
                }
                THPPlayerPlay();
                gAttractMovieState = NATTRACTMODE_MOVIE_STATE_PREPARED;
                VIWaitForRetrace();
                gAttractMovieRetraceCountdown = NATTRACTMODE_MOVIE_RETRACE_COUNTDOWN;
                gAttractMovieIdleFrameCount = 0;
                if ((int)gTitleMenuSelection == TITLE_MENU_ATTRACT_MOVIE_STATE)
                {
                    Movie_SetVolumeFade(NATTRACTMODE_MOVIE_VOLUME_TITLE,
                                        NATTRACTMODE_MOVIE_VOLUME_FADE_IMMEDIATE);
                }
                else
                {
                    Movie_SetVolumeFade(NATTRACTMODE_MOVIE_VOLUME_MUTED,
                                        NATTRACTMODE_MOVIE_VOLUME_FADE_IMMEDIATE);
                }
            }
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: TitleMenu_render
 * EN v1.0 Address: 0x801165BC
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void TitleMenu_render(u8* param_1)
{
    int menuAction;

    if (shouldShowCredits(param_1) != 0)
    {
        creditsStart_();
        return;
    }

    menuAction = (*gCameraInterface)->getMode();
    if (menuAction == TITLE_MENU_CAMERA_ACTION_ACTIVE)
    {
        gameTextSetDrawFunc(titleScreenTextDrawFunc);
        titleScreenPositionElements(lbl_803E1D10 + (f32)(gTitleMenuSelectionFade * 0x1a4) / lbl_803E1D14,
                                    lbl_803E1D18);
        gameTextBoxFn_80134d40(0, 0, 0);
        (*gScreenTransitionInterface)->getProgress();
        (*(code*)((int)gTitleMenuLinkInterface->vtable + 0x30))(0xff);
        (*(code*)((int)gTitleMenuLinkInterface->vtable + 0x10))(param_1);
        gameTextSetDrawFunc(0);
        titleScreenShowCopyright(gAttractMoviePlaybackEnabled);
    }
}

/* Trivial 4b 0-arg blr leaves. */
void TitleMenu_frameEnd(void)
{
}
