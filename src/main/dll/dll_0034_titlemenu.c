/* DLL 0x0034 — title menu [8011611C-801166C8) */
#include "main/dll/FRONT/dll_39.h"
#include "main/dll/FRONT/dll_44.h"
#include "main/dll/FRONT/picmenu.h"
#include "main/camera_interface.h"
#include "main/screen_transition.h"
#include "main/audio/sfx_ids.h"
#include "main/mm.h"
#include "main/gameplay_runtime.h"
#include "dolphin/vi.h"
#include "main/pad.h"
#include "main/sfa_extern_decls.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
extern BOOL Movie_SetVolumeFade(int volume, int fadeFrames);
extern bool prepareAttractMode();
extern void titleScreenShowCopyright(u8 arg);
extern void gameTextBoxFn_80134d40(int p1, int p2, u32 p3);
extern void titleScreenPositionElements(f32 a, f32 b);
extern void titleScreenTextDrawFunc(void);

static char sNRarewareReportTag[] = "n_rareware\n";

extern int mmSetFreeDelay(int v);
extern void printHeapStats(int mode);
extern void OSReport(const char* msg, ...);
extern TitleMenuControl* gTitleMenuLinkInterface;
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

/* TitleMenuTextEntry.flags: row is hidden / non-selectable (cleared on the
   highlighted entry, set on the rest). */
#define TITLE_MENU_TEXT_ENTRY_HIDDEN 0x4000

#pragma dont_inline on

extern void buttonDisable(int port, u32 mask);
extern void padClearAnalogInputY(int port);
extern void padClearAnalogInputX(int port);
extern void padGetAnalogInput(int controller, s8* dpad, s8* face);
extern void setDrawLights(int v);
extern void setIsOvercast(int v);
extern void memCardFn_8007dd04(u8 retry);
extern void loadSaveSettings(void);
extern int saveFn_800e8508(void);
extern void titleDoLoadSave(void);
extern float titleScreenGetCamProgress(void);
extern void titleScreenFn_80130464(u8 v);

extern void titleScreenFn_801368a4(u8 arg);
extern void titleScreenFn_801368c4(s8 arg);
extern void saveFn_8007d960(int);
extern u8 framesThisStep;
extern u8 lbl_803DB424;
extern TitleMenuTextEntry lbl_8031A214[4];
extern u8 gTitleMenuPreviousSelection;
extern s8 gTitleMenuSelectionFadeStep;
extern u8 lbl_803DD618;
extern u8 gAttractMovieAutoplayEnabled;
extern s32 gTitleMenuInputCooldown;
extern u8 gAttractMovieReplayCountdown;
extern u8 gTitleMenuReadyForInput;
extern s8 gTitleMenuNextDllId;
extern s8 gTitleMenuLoadDelay;
extern u8 gTitleMenuPanelOpen;
extern u8 gAttractMovieLoopCompleted;
extern u8 lbl_803DD6F8;
extern f32 lbl_803E1D28;
extern void audioSetVolumes(u8 volume, u16 time, int musicFlag, int fxFlag, int streamFlag);
extern void audioStopByMask(int mask);
extern void audioFn_8000b694(int arg);
extern int getUiDllFn_80014930(void);
extern void gameTimerStop(void);
extern void gameTextLoadDir(int dirId);

extern u8* lbl_803DD498;

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

#pragma dont_inline reset

void n_attractmode_prepareMovie(void)
{
    extern char sNAttractModeStringBlock[]; /* #57 */
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
        ok = movieLoad(attractModeStrings + NATTRACTMODE_MOVIE_PATH_OFFSET,
                       NATTRACTMODE_MOVIE_START_FRAME_DEFAULT);
        if (ok == 0)
        {
            AttractMovieAudio_Shutdown();
        }
        else
        {
            THPPlayerGetVideoInfo(&gAttractMovieDims);
            gAttractMovieOffsetX = ((u32)gRenderModeObj[2] - gAttractMovieDims.width) >> 1;
            gAttractMovieOffsetY = ((u32)gRenderModeObj[3] - gAttractMovieDims.height) >> 1;
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

void TitleMenu_render(u8* obj)
{
    extern u8 shouldShowCredits(u8 * obj); /* #57 */
    int menuAction;

    if (shouldShowCredits(obj) != 0)
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
        (*(VtableFn*)((int)gTitleMenuLinkInterface->vtable + 0x30))(0xff);
        (*(VtableFn*)((int)gTitleMenuLinkInterface->vtable + 0x10))(obj);
        gameTextSetDrawFunc(0);
        titleScreenShowCopyright(gAttractMoviePlaybackEnabled);
    }
}

void TitleMenu_frameEnd(void)
{
}

#define TitleMenu_GetMenuId() (*(int (**)(void))((int)*gCameraInterface + 0x10))()
#define TitleMenu_SetMenuState(state, arg) (*(void (**)(int, int))((int)*gCameraInterface + 0x60))(state,arg)
#define TitleMenu_GetFadeState() (*(int (**)(void))((int)gTitleMenuLinkInterface->vtable + 0xc))()
#define TitleMenu_GetSelection() (*(int (**)(void))((int)gTitleMenuLinkInterface->vtable + 0x14))()
#define TitleMenu_BindEntries() (*(void (**)(TitleMenuTextEntry *))((int)gTitleMenuLinkInterface->vtable + 0x2c))(lbl_8031A214)
#define TitleMenu_ClearPanel() (*(void (**)(void))((int)gTitleMenuLinkInterface->vtable + 8))()
#define TitleMenu_OpenPanel() (*(void (**)(TitleMenuTextEntry *, int, int, int, int, int, int, int, int, int, int, int))((int)gTitleMenuLinkInterface->vtable + 4))(lbl_8031A214,9,5,0,0,0,0x14,200,0xff,0xff,0xff,0xff)
#define TitleMenu_SetPanelSelection(selection) (*(void (**)(int))((int)gTitleMenuLinkInterface->vtable + 0x18))(selection)
#define TitleMenu_SetEntryHighlight(entry) \
  do { \
    int i; \
    for (i = 0; i < 4; i++) { \
      if (i == (entry)) { \
        lbl_8031A214[i].flags &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN; \
      } else { \
        lbl_8031A214[i].flags |= TITLE_MENU_TEXT_ENTRY_HIDDEN; \
      } \
    } \
    TitleMenu_BindEntries(); \
  } while (0)
#define TitleMenu_ReloadSaveSettings() \
  do { \
    int result; \
    result = saveFn_800e8508(); \
    if ((result == 0) && (lbl_803DB424 != 0)) { \
      memCardFn_8007dd04(1); \
    } \
    loadSaveSettings(); \
  } while (0)

int TitleMenu_run(void)
{
    extern u8 shouldShowCredits(void); /* #57 */
    int menuId;
    int buttons;
    int sum;
    s8 previousFadeTimer;
    int frames;
    u8 inputPressed;
    s8 dpad;
    s8 face;

    previousFadeTimer = gTitleMenuLoadDelay;
    frames = framesThisStep;
    if (lbl_803DB424 == 0xfe)
    {
        TitleMenu_ReloadSaveSettings();
        if (lbl_803DB424 == 0xfe)
        {
            lbl_803DB424 = 1;
        }
    }
    if ((gAttractMovieAutoplayEnabled == 0) && (gTitleMenuInputCooldown == 0))
    {
        n_attractmode_releaseMovieBuffers();
        loadUiDll(1);
        doNothing_onSaveSelectScreenExit();
        titleScreenFn_801368d4();
        buttons = mmSetFreeDelay(0);
        mapUnload(0x3d, 0x20000000);
        mmSetFreeDelay(buttons);
        titleDoLoadSave();
        return 0;
    }

    setIsOvercast(0);
    setDrawLights(0);
    if (shouldShowCredits() != 0)
    {
        return 0;
    }

    if (gTitleMenuInputCooldown != 0)
    {
        gTitleMenuInputCooldown--;
    }
    if (gAttractMoviePreparePending != 0)
    {
        n_attractmode_prepareMovie();
    }
    if ((gAttractMovieRetraceCountdown != 0) && (--gAttractMovieRetraceCountdown == 0) &&
        (gAttractMoviePlaybackEnabled != 0))
    {
        Movie_SetVolumeFade(NATTRACTMODE_MOVIE_VOLUME_TITLE, NATTRACTMODE_MOVIE_VOLUME_FADE_LONG);
    }
    if ((gAttractMovieState == NATTRACTMODE_MOVIE_STATE_PREPARED) &&
        (++gAttractMovieIdleFrameCount > NATTRACTMODE_MOVIE_RETRACE_COUNTDOWN))
    {
        n_attractmode_releaseMovieBuffers();
    }
    if (((gAttractMovieState == NATTRACTMODE_MOVIE_STATE_PREPARED) &&
            (gAttractMoviePlaybackEnabled != 0)) &&
        (gTitleMenuReadyForInput != 0))
    {
        buttons = getButtonsJustPressed(0);
        padGetAnalogInput(0, &dpad, &face);
        buttonDisable(0, buttons);
        padClearAnalogInputX(0);
        padClearAnalogInputY(0);

        inputPressed = 0;
        if ((gAttractMovieLoopCompleted != 0) && (gTitleMenuInputCooldown == 0))
        {
            inputPressed = 1;
        }
        else if ((buttons != 0) || ((dpad != 0 || (face != 0))))
        {
            inputPressed = 1;
        }
        if (*(u8*)&gAttractMovieLoopCompleted != 0)
        {
            gAttractMovieLoopCompleted = 0;
        }
        if (inputPressed)
        {
            if (((buttons != 0) || (dpad != 0)) || (face != 0))
            {
                gAttractMovieReplayCountdown = 2;
            }
            else
            {
                gAttractMovieReplayCountdown = 1;
                gTitleMenuInputCooldown = TITLE_MENU_ATTRACT_INPUT_COOLDOWN_FRAMES;
            }
            TitleMenu_SetPanelSelection(0);
            gAttractMoviePlaybackEnabled = 0;
            TitleMenu_SetMenuState(0, 1);
            if (lbl_803DB424 == 0xff)
            {
                TitleMenu_ReloadSaveSettings();
                if (lbl_803DB424 == 0xff)
                {
                    lbl_803DB424 = 1;
                }
            }
        }
    }
    else if ((gTitleMenuReadyForInput != 0) && (gAttractMoviePlaybackEnabled == 0))
    {
        buttons = getButtonsJustPressed(0);
        padGetAnalogInput(0, &dpad, &face);
        if ((buttons != 0) || ((dpad != 0 || (face != 0))))
        {
            gAttractMovieReplayCountdown = 2;
        }
        else if (gAttractMovieLoopCompleted != 0)
        {
            gAttractMovieLoopCompleted = 0;
            if (gTitleMenuInputCooldown == 0)
            {
                gTitleMenuInputCooldown = TITLE_MENU_ATTRACT_INPUT_COOLDOWN_FRAMES;
                gAttractMovieReplayCountdown--;
                if (gAttractMovieReplayCountdown == 0)
                {
                    gAttractMovieReplayCountdown = 1;
                    TitleMenu_SetMenuState(TITLE_MENU_ATTRACT_MOVIE_STATE, 1);
                    gAttractMoviePlaybackEnabled = 1;
                    gTitleMenuSelectionFadeStep = -TITLE_MENU_SELECTION_FADE_STEP;
                }
            }
        }
    }

    if (frames > 3)
    {
        frames = 3;
    }
    if (gTitleMenuLoadDelay > 0)
    {
        gTitleMenuLoadDelay -= frames;
    }
    menuId = TitleMenu_GetMenuId();
    if (menuId != TITLE_MENU_CAMERA_ACTION_ACTIVE)
    {
        gTitleMenuReadyForInput = 0;
        return 0;
    }

    gTitleMenuReadyForInput = 1;
    if (gTitleMenuNextDllId != 0)
    {
        if (((previousFadeTimer <= 12) || (gTitleMenuLoadDelay > 12)) && (gTitleMenuLoadDelay <= 0))
        {
            TitleMenu_ClearPanel();
            titleScreenFn_8005cdd4(0);
            setLinkNotRotated();
            loadUiDll(gTitleMenuNextDllId);
        }
        return gTitleMenuLoadDelay <= 12;
    }

    menuId = TitleMenu_GetFadeState();
    gTitleMenuSelection = TitleMenu_GetSelection();
    if (((lbl_803E1D28 == titleScreenGetCamProgress()) &&
            (gTitleMenuSelectionFade < TITLE_MENU_SELECTION_FADE_MAX)) &&
        (gAttractMoviePlaybackEnabled == 0))
    {
        gTitleMenuSelectionFadeStep = TITLE_MENU_SELECTION_FADE_STEP;
        if (gTitleMenuSelection == 0)
        {
            lbl_803DD618 = 1;
        }
        else
        {
            lbl_803DD618 = 0;
        }
    }
    else if (gTitleMenuPreviousSelection != gTitleMenuSelection)
    {
        TitleMenu_SetMenuState(gTitleMenuSelection, 1);
        Sfx_PlayFromObject(0, SFXTRIG_menu_fox_select);
        gTitleMenuSelectionFadeStep = -TITLE_MENU_SELECTION_FADE_STEP;
        gTitleMenuPreviousSelection = gTitleMenuSelection;
        titleScreenFn_80130464(0);
    }
    sum = gTitleMenuSelectionFade + gTitleMenuSelectionFadeStep;
    if (sum >= TITLE_MENU_SELECTION_FADE_MAX)
    {
        gTitleMenuSelectionFade = TITLE_MENU_SELECTION_FADE_MAX;
        gTitleMenuSelectionFadeStep = 0;
        titleScreenFn_80130464(1);
    }
    else if (sum <= 0)
    {
        TitleMenu_SetEntryHighlight(gTitleMenuSelection);
        gTitleMenuSelectionFade = 0;
        gTitleMenuSelectionFadeStep = 0;
        if (gTitleMenuSelection != 0)
        {
            lbl_803DD618 = 0;
        }
    }
    else
    {
        gTitleMenuSelectionFade += gTitleMenuSelectionFadeStep;
    }
    if (gTitleMenuPanelOpen == 0)
    {
        if (menuId == 1)
        {
            TitleMenu_ClearPanel();
            TitleMenu_OpenPanel();
            gTitleMenuPanelOpen = 1;
        }
    }
    else
    {
        titleScreenFn_801368c4(gTitleMenuSelection);
        if ((menuId == 1) && (gTitleMenuSelectionFade == TITLE_MENU_SELECTION_FADE_MAX))
        {
            titleScreenFn_801368a4(1);
            gTitleMenuLoadDelay = 1;
            titleScreenFn_80130464(1);
            Sfx_PlayFromObject(0, SFXsp_snrin2_c);
            switch (gTitleMenuSelection)
            {
            case 0:
                gTitleMenuNextDllId = 5;
                break;
            case 1:
                gTitleMenuNextDllId = 7;
                lbl_803DD6F8 = 0;
                break;
            case 2:
                gTitleMenuNextDllId = 7;
                lbl_803DD6F8 = 1;
                break;
            case 3:
                gTitleMenuNextDllId = 7;
                lbl_803DD6F8 = 2;
                break;
            }
            return 0;
        }
        titleScreenFn_801368a4(0);
    }
    return 0;
}

void TitleMenu_release(void)
{
    setLinkNotRotated();
    titleScreenFn_80130464(1);
    saveFn_8007d960(1);
}

void TitleMenu_setSelection(int selection)
{
    u8 v = selection;
    gTitleMenuSelection = v;
    gTitleMenuPreviousSelection = TITLE_MENU_SELECTION_INVALID;
    (*(*(void (**)(int))((int)gTitleMenuLinkInterface->vtable + 0x18)))(v);
}

void TitleMenu_initialise(void)
{
    extern TitleMenuTextEntry sNAttractModeStringBlock[1]; /* #57 */
    int i;
    int mode;

    if ((lbl_803DD498[0x21] & 0x80) != 0)
    {
        gAttractMovieAutoplayEnabled = 0;
    }
    else
    {
        gAttractMovieAutoplayEnabled = 1;
    }
    if (lbl_803DB424 >= 0xfe)
    {
        saveFn_8007d960(0);
    }
    gameTextLoadDir(0x15);
    gTitleMenuNextDllId = 0;
    gTitleMenuLoadDelay = 0;
    mode = getUiDllFn_80014930();
    if (mode == 3)
    {
        ((void (**)(TitleMenuTextEntry*, int, int, int, int, int, int, int, int, int, int, int))
            gTitleMenuLinkInterface->vtable)[1](sNAttractModeStringBlock, 1, 0, 0, 0, 0, 0x14, 200, 0xff, 0xff, 0xff, 0xff);
        gTitleMenuPanelOpen = 0;
    }
    else
    {
        ((void (**)(TitleMenuTextEntry*, int, int, int, int, int, int, int, int, int, int, int))
            gTitleMenuLinkInterface->vtable)[1](lbl_8031A214, 4, 0, 0, 0, 0, 0x14, 200, 0xff, 0xff, 0xff, 0xff);
        gTitleMenuPanelOpen = 1;
    }
    ((void (**)(int))gTitleMenuLinkInterface->vtable)[6](gTitleMenuSelection);
    titleScreenFn_801368a4(0);

    mode = getUiDllFn_80014930();
    if ((((mode == 0xd) || (mode = getUiDllFn_80014930(), mode == 7)) ||
            (mode = getUiDllFn_80014930(), mode == 6)) ||
        (mode = getUiDllFn_80014930(), mode == 5))
    {
        (*gScreenTransitionInterface)->step(0x23, 5);
    }
    else
    {
        audioStopByMask(0xf);
        (*gScreenTransitionInterface)->step(0x3c, 1);
    }

    setLinkIsRotated();
    for (i = 0; i < 4; i++)
    {
        if (i == gTitleMenuSelection)
        {
            lbl_8031A214[i].flags &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN;
        }
        else
        {
            lbl_8031A214[i].flags |= TITLE_MENU_TEXT_ENTRY_HIDDEN;
        }
    }
    ((void (**)(TitleMenuTextEntry*))gTitleMenuLinkInterface->vtable)[11](lbl_8031A214);
    gAttractMoviePreparePending = 0;
    gAttractMovieRetraceCountdown = 0;
    gAttractMovieReplayCountdown = 1;
    gTitleMenuInputCooldown = 0x3c;
    gAttractMovieLoopCompleted = 0;

    if ((gAttractMovieAutoplayEnabled != 0) &&
        ((gAttractMovieState == NATTRACTMODE_MOVIE_READY) ||
            (gAttractMovieState == NATTRACTMODE_MOVIE_STATE_RELEASED)))
    {
        n_attractmode_prepareMovie();
        titleScreenPositionElements(lbl_803E1D10, lbl_803E1D18);
        gAttractMoviePlaybackEnabled = 1;
        Movie_SetVolumeFade(0, 0);
        audioSetVolumes(0, 10, 1, 0, 0);
        gTitleMenuSelectionFade = 0;
    }
    else
    {
        titleScreenPositionElements(lbl_803E1D10, lbl_803E1D18);
        gAttractMoviePlaybackEnabled = 0;
        Movie_SetVolumeFade(0, 1);
    }
    setIsOvercast(0);
    setDrawLights(0);
    gTitleMenuReadyForInput = 0;
    envFxActFn_800887f8(0);
    gameTimerStop();
    audioFn_8000b694(0);
    gAttractMovieIdleFrameCount = 0;
}

TitleMenuTextEntry sNAttractModeStringBlock[1] = {
    {
        0x036D,
        { 0x00, 0x35, 0x01, 0x40, 0x01, 0x90, 0x00, 0x00, 0x01, 0x40, 0x01, 0x90, 0x00, 0x00 },
        -1,
        { 0x00, 0xC8 },
        0x0280,
        { 0, 0, -1, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    },
};

/* descriptor/ptr table auto 0x8031a214-0x8031a3b0 */
u32 lbl_8031A214[60] = { 0x03310011, 0x0140010a, 0x00000140, 0x00b40000, 0xffffffff, 0x00640200, 0x00000301, 0xffffff00, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x035a0011, 0x0140013d, 0x00000140, 0x00bb0000, 0xffffffff, 0x008c0200, 0x00000002, 0xffffff00, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x035c0011, 0x0140013d, 0x00000140, 0x00bb0000, 0xffffffff, 0x00b40200, 0x00000103, 0xffffff00, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x035b0011, 0x01400170, 0x00000140, 0x00bb0000, 0xffffffff, 0x008c0200, 0x00000200, 0xffffff00, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
u32 lbl_8031A304[43] = { 0x00000000, 0x00000000, 0x00000000, 0x00050000, (u32)TitleMenu_initialise, (u32)TitleMenu_release, 0x00000000, (u32)TitleMenu_run, (u32)TitleMenu_frameEnd, (u32)TitleMenu_render, 0x73746172, 0x666f782e, 0x74687000, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x20206d61, 0x6c6c6f63, 0x20666f72, 0x206d6f76, 0x69652066, 0x61696c65, 0x640a0000, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x20205245, 0x53545255, 0x43542066, 0x6f72206d, 0x6f766965, 0x0a000000, 0x6e5f6174, 0x74726163, 0x746d6f64, 0x652e6300, 0x4661696c, 0x20746f20, 0x70726570, 0x6172650a, 0x00000000 };
