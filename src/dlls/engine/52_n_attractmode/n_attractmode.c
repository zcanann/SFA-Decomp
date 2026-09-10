#include "main/sky_api.h"
#include "main/attract_movie_api.h"
#include "main/screen_transition.h"
#include "main/mm.h"
#include "main/pad.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/textrender_api.h"
#include "main/dll/dll_0015_save_settings.h"
#include "main/dll/savegame.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "track/intersect_card_api.h"
#include "main/dll/dll_0057_cameramodetitle.h"
#include "main/dll/dll_02C0_front.h"
#include "main/dll/dll_003C_link.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_003C_link_api.h"
#include "main/dll/front_game_text_box_api.h"
#include "main/game_timer_control_api.h"
#include "main/lightmap_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/map_load.h"
#include "main/model_engine.h"
#include "main/dll/FRONT/dll_3B.h"
#include "main/dll/dll_0037_optionsscreen.h"
#include "dolphin/os.h"
#include "dolphin/os/OSReport.h"
#include "dolphin/os/OSRtc.h"
#include "dolphin/vi.h"
#include "main/dll/FRONT/dll_39.h"
#include "main/dll/FRONT/dll_44.h"
#include "main/dll/dll_3e_api.h"
#include "main/pi_dolphin.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/thp/THPDraw.h"
#include "dolphin/thp/THPPlayer.h"
#include "main/dll/FRONT/picmenu.h"
#include "dlls/object_descriptor.h"
#include "main/camera_interface.h"

#if defined(VERSION_GSAE01_rev1)
#define NATTRACTMODE_PREPARE_FAIL_LINE 0x33E
#elif defined(VERSION_GSAP01)
#define NATTRACTMODE_PREPARE_FAIL_LINE 0x33A
#elif defined(VERSION_GSAP01_rev1)
#define NATTRACTMODE_PREPARE_FAIL_LINE 0x34D
#else
#define NATTRACTMODE_PREPARE_FAIL_LINE 0x2FB
#endif

#define TITLE_MENU_LANGUAGE_SETUP_NONE      0
#define TITLE_MENU_LANGUAGE_SETUP_REQUESTED 1
#define TITLE_MENU_LANGUAGE_SETUP_OPEN      2
#define TITLE_MENU_LANGUAGE_SETUP_RESTORE   3

u8 gTitleMenuPanelOpen;
s8 gTitleMenuLoadDelay;
s8 gTitleMenuNextDllId;
u8 gAttractMoviePlaybackEnabled;
u8 gTitleMenuReadyForInput;
u8 gAttractMovieRetraceCountdown;
u8 gAttractMovieReplayCountdown;
s32 gTitleMenuInputCooldown;
int gAttractMovieOffsetX;
int gAttractMovieOffsetY;
NAttractModeMovieDims gAttractMovieDims;
void* gAttractMovieBuffer0;
void* gAttractMovieBuffer1;
void* gAttractMovieBuffer2;
void* gAttractMovieBuffer3;
void* gAttractMovieOptionalBuffer;
void* gAttractMovieWorkBuffer;
void* gAttractMovieScratchBuffer;
u8 gAttractMovieAutoplayEnabled;
#if !defined(VERSION_GSAE01) && !defined(VERSION_GSAJ01)
s32 gTitleMenuLanguageSetupState;
#endif
u8 gAttractMoviePreparePending;
u8 lbl_803DD618;
s8 gTitleMenuSelectionFadeStep;
u8 gTitleMenuSelectionFade;
u8 gTitleMenuPreviousSelection;
u8 gTitleMenuSelection;
s32 gAttractMovieState;

extern TitleMenuTextEntry gTitleMenuEntries[4];
extern TitleMenuTextEntry gTitleMenuClosedPanelEntry[1];

TitleMenuTextEntry gTitleMenuClosedPanelEntry[1] = {
    {
        0x036D, 0x0035,    320,
        400,    0,         320,
        400,    {0, 0},    -1,
        0x00C8, 0x0280,    {0x00, 0x00},
        -1,     -1,        -1,
        -1,     -1,        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,      {0, 0, 0},
    },
};

TitleMenuTextEntry gTitleMenuEntries[4] = {
    {
        0x0331, 0x0011,    320,
        266,    0,         320,
        180,    {0, 0},    -1,
        0x0064, 0x0200,    {0x00, 0x00},
        3,      1,         -1,
        -1,     -1,        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,      {0, 0, 0},
    },
    {
        0x035A, 0x0011,    320,
        317,    0,         320,
        187,    {0, 0},    -1,
        0x008C, 0x0200,    {0x00, 0x00},
        0,      2,         -1,
        -1,     -1,        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,      {0, 0, 0},
    },
    {
        0x035C, 0x0011,    320,
        317,    0,         320,
        187,    {0, 0},    -1,
        0x00B4, 0x0200,    {0x00, 0x00},
        1,      3,         -1,
        -1,     -1,        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,      {0, 0, 0},
    },
    {
        0x035B, 0x0011,    320,
        368,    0,         320,
        187,    {0, 0},    -1,
        0x008C, 0x0200,    {0x00, 0x00},
        2,      0,         -1,
        -1,     -1,        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        0,      {0, 0, 0},
    },
};
ObjectDescriptor6 n_attractmode_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)TitleMenu_initialise,
    (ObjectDescriptorCallback)TitleMenu_release,
    0,
    (ObjectDescriptorCallback)TitleMenu_run,
    (ObjectDescriptorCallback)TitleMenu_frameEnd,
    (ObjectDescriptorCallback)TitleMenu_render,
};

void n_attractmode_releaseMovieBuffers(void) {
    int freeDelay;

    if (gAttractMovieState == NATTRACTMODE_MOVIE_STATE_PREPARED) {
        THPPlayerStop();
        AttractMovie_CloseFile();
        AttractMovieAudio_Shutdown();
        freeDelay = mmSetFreeDelay(0);
        if (gAttractMovieBuffer0 != 0) {
            mm_free(gAttractMovieBuffer0);
            gAttractMovieBuffer0 = 0;
        }
        if (gAttractMovieBuffer1 != 0) {
            mm_free(gAttractMovieBuffer1);
            gAttractMovieBuffer1 = 0;
        }
        if (gAttractMovieBuffer2 != 0) {
            mm_free(gAttractMovieBuffer2);
            gAttractMovieBuffer2 = 0;
        }
        if (gAttractMovieBuffer3 != 0) {
            mm_free(gAttractMovieBuffer3);
            gAttractMovieBuffer3 = 0;
        }
        if (gAttractMovieOptionalBuffer != 0) {
            mm_free(gAttractMovieOptionalBuffer);
            gAttractMovieOptionalBuffer = 0;
        }
        if (gAttractMovieWorkBuffer != 0) {
            mm_free(gAttractMovieWorkBuffer);
            gAttractMovieWorkBuffer = 0;
        }
        if (gAttractMovieScratchBuffer != 0) {
            mm_free(gAttractMovieScratchBuffer);
            gAttractMovieScratchBuffer = 0;
        }
        mmSetFreeDelay(freeDelay);
        gAttractMovieState = NATTRACTMODE_MOVIE_STATE_RELEASED;
        gAttractMoviePreparePending = NATTRACTMODE_MOVIE_BUSY;
    }
    return;
}

void n_attractmode_prepareMovie(void) {
    int ok;
    int freeDelay;
    int movieBuffer1Size;
    int movieBuffer2Size;
    int movieBuffer3Size;
    u32 optionalBufferSize;
    int workBufferSize;
    u32 movieBuffer0Size[3];

    gAttractMoviePreparePending = NATTRACTMODE_MOVIE_BUSY;
    ok = AttractMovieAudio_Init(NATTRACTMODE_MOVIE_SETUP_ID);
    if (ok != 0) {
        ok = movieLoad("starfox.thp", NATTRACTMODE_MOVIE_START_FRAME_DEFAULT);
        if (ok == 0) {
            AttractMovieAudio_Shutdown();
        } else {
            THPPlayerGetVideoInfo(&gAttractMovieDims);
            gAttractMovieOffsetX = ((u32)gRenderModeObj->fbWidth - gAttractMovieDims.width) >> 1;
            gAttractMovieOffsetY = ((u32)gRenderModeObj->efbHeight - gAttractMovieDims.height) >> 1;
            AttractMovie_GetBufferSizes(movieBuffer0Size, &movieBuffer1Size, &movieBuffer2Size, &movieBuffer3Size,
                                        &optionalBufferSize, &workBufferSize);
            gAttractMovieBuffer0 = mmAlloc(movieBuffer0Size[0], NATTRACTMODE_MOVIE_HEAP, 0);
            gAttractMovieBuffer1 = mmAlloc(movieBuffer1Size, NATTRACTMODE_MOVIE_HEAP, 0);
            gAttractMovieBuffer2 = mmAlloc(movieBuffer2Size, NATTRACTMODE_MOVIE_HEAP, 0);
            gAttractMovieBuffer3 = mmAlloc(movieBuffer3Size, NATTRACTMODE_MOVIE_HEAP, 0);
            if (optionalBufferSize != NATTRACTMODE_OPTIONAL_BUFFER_SIZE_NONE) {
                gAttractMovieOptionalBuffer = mmAlloc(optionalBufferSize, NATTRACTMODE_MOVIE_HEAP, 0);
            } else {
                gAttractMovieOptionalBuffer = 0;
            }
            gAttractMovieWorkBuffer = mmAlloc(workBufferSize, NATTRACTMODE_MOVIE_HEAP, 0);
            gAttractMovieScratchBuffer = mmAlloc(NATTRACTMODE_WORK_BUFFER_SIZE, NATTRACTMODE_MOVIE_HEAP, 0);
            if (((((gAttractMovieBuffer0 == 0) || (gAttractMovieBuffer1 == 0)) || (gAttractMovieBuffer2 == 0)) ||
                 ((gAttractMovieBuffer3 == 0 || ((gAttractMovieOptionalBuffer == 0 &&
                                                  (optionalBufferSize != NATTRACTMODE_OPTIONAL_BUFFER_SIZE_NONE)))))) ||
                ((gAttractMovieWorkBuffer == 0 || (gAttractMovieScratchBuffer == 0)))) {
                AttractMovieAudio_Shutdown();
                freeDelay = mmSetFreeDelay(0);
                if (gAttractMovieBuffer0 != 0) {
                    mm_free(gAttractMovieBuffer0);
                    gAttractMovieBuffer0 = 0;
                }
                if (gAttractMovieBuffer1 != 0) {
                    mm_free(gAttractMovieBuffer1);
                    gAttractMovieBuffer1 = 0;
                }
                if (gAttractMovieBuffer2 != 0) {
                    mm_free(gAttractMovieBuffer2);
                    gAttractMovieBuffer2 = 0;
                }
                if (gAttractMovieBuffer3 != 0) {
                    mm_free(gAttractMovieBuffer3);
                    gAttractMovieBuffer3 = 0;
                }
                if (gAttractMovieOptionalBuffer != 0) {
                    mm_free(gAttractMovieOptionalBuffer);
                    gAttractMovieOptionalBuffer = 0;
                }
                if (gAttractMovieWorkBuffer != 0) {
                    mm_free(gAttractMovieWorkBuffer);
                    gAttractMovieWorkBuffer = 0;
                }
                if (gAttractMovieScratchBuffer != 0) {
                    mm_free(gAttractMovieScratchBuffer);
                    gAttractMovieScratchBuffer = 0;
                }
                mmSetFreeDelay(freeDelay);
                OSReport("^^^^^^^^^^^^^^^^  malloc for movie failed\n");
                printHeapStats(1);
                defragMemory(0);
                OSReport("^^^^^^^^^^^^^^^^  RESTRUCT for movie\n");
                printHeapStats(1);
            } else {
                gAttractMoviePreparePending = NATTRACTMODE_MOVIE_READY;
                DCInvalidateRange(gAttractMovieBuffer0, movieBuffer0Size[0]);
                DCInvalidateRange(gAttractMovieBuffer1, movieBuffer1Size);
                DCInvalidateRange(gAttractMovieBuffer2, movieBuffer2Size);
                DCInvalidateRange(gAttractMovieBuffer3, movieBuffer3Size);
                if (gAttractMovieOptionalBuffer != 0) {
                    DCInvalidateRange(gAttractMovieOptionalBuffer, optionalBufferSize);
                }
                DCInvalidateRange(gAttractMovieWorkBuffer, workBufferSize);
                DCInvalidateRange(gAttractMovieScratchBuffer, NATTRACTMODE_WORK_BUFFER_SIZE);
                AttractMovie_AssignBuffers(gAttractMovieBuffer0, gAttractMovieBuffer1, gAttractMovieBuffer2,
                                           gAttractMovieBuffer3, gAttractMovieOptionalBuffer, gAttractMovieWorkBuffer);
                ok = prepareAttractMode(0, 1);
                if (ok == 0) {
                    OSPanic("n_attractmode.c", NATTRACTMODE_PREPARE_FAIL_LINE, "Fail to prepare\n");
                }
                THPPlayerPlay();
                gAttractMovieState = NATTRACTMODE_MOVIE_STATE_PREPARED;
                VIWaitForRetrace();
                gAttractMovieRetraceCountdown = NATTRACTMODE_MOVIE_RETRACE_COUNTDOWN;
                gAttractMovieIdleFrameCount = 0;
                if ((int)gTitleMenuSelection == TITLE_MENU_ATTRACT_MOVIE_STATE) {
                    Movie_SetVolumeFade(NATTRACTMODE_MOVIE_VOLUME_TITLE, NATTRACTMODE_MOVIE_VOLUME_FADE_IMMEDIATE);
                } else {
                    Movie_SetVolumeFade(NATTRACTMODE_MOVIE_VOLUME_MUTED, NATTRACTMODE_MOVIE_VOLUME_FADE_IMMEDIATE);
                }
            }
        }
    }
    return;
}

void TitleMenu_render(int obj) {
    int menuAction;

    if (shouldShowCredits() != 0) {
        creditsStart_();
        return;
    }

    menuAction = (*gCameraInterface)->getMode();
    if (menuAction == TITLE_MENU_CAMERA_ACTION_ACTIVE) {
        gameTextSetDrawFunc(titleScreenTextDrawFunc);
        titleScreenPositionElements(-380.0f + (f32)(gTitleMenuSelectionFade * 0x1a4) / 255.0f, 254.0f);
        titleScreenDrawMenuFrame(0, 0, 0);
        (*gScreenTransitionInterface)->getProgress();
        gTitleMenuLinkInterface->vtable->setOpacity(0xff);
        gTitleMenuLinkInterface->vtable->render(obj);
        gameTextSetDrawFunc(0);
        titleScreenShowCopyright(gAttractMoviePlaybackEnabled);
    }
}

void TitleMenu_frameEnd(void) {
}

#define TitleMenu_SetEntryHighlight(entry)                                                                             \
    do {                                                                                                               \
        int i;                                                                                                         \
        for (i = 0; i < 4; i++) {                                                                                      \
            if (i == (entry)) {                                                                                        \
                gTitleMenuEntries[i].flags &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN;                                           \
            } else {                                                                                                   \
                gTitleMenuEntries[i].flags |= TITLE_MENU_TEXT_ENTRY_HIDDEN;                                            \
            }                                                                                                          \
        }                                                                                                              \
        gTitleMenuLinkInterface->vtable->copyItems(gTitleMenuEntries);                                                 \
    } while (0)
static inline void TitleMenu_CreateSaveFile(void) {
#if defined(VERSION_GSAP01_rev1)
    if (cardCreateSaveFile(1) != 0) {
        loadGameOptions();
    }
#else
    cardCreateSaveFile(1);
#endif
}

#define TitleMenu_ReloadSaveSettings()                                                                                 \
    do {                                                                                                               \
        int result;                                                                                                    \
        result = loadGameOptions();                                                                                    \
        if ((result == 0) && (gSaveGameEnabled != 0)) {                                                                \
            TitleMenu_CreateSaveFile();                                                                                \
        }                                                                                                              \
        loadSaveSettings();                                                                                            \
    } while (0)

int TitleMenu_run(void) {
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
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
    if (gTitleMenuLanguageSetupState == TITLE_MENU_LANGUAGE_SETUP_RESTORE) {
        SaveData* options;
        u8 languageIndex;
        u8 subtitlesEnabled;

        gTitleMenuLanguageSetupState = TITLE_MENU_LANGUAGE_SETUP_NONE;
        options = getSaveFileStruct();
        languageIndex = options->languageIndex;
        subtitlesEnabled = options->subtitlesEnabled;
        if (loadGameOptions() == 0 && gSaveGameEnabled != 0) {
            TitleMenu_CreateSaveFile();
            options->languageIndex = languageIndex;
            options->subtitlesEnabled = subtitlesEnabled;
            if (gSaveGameEnabled != 0) {
                saveGameOptions();
            }
        }
        options->languageIndex = languageIndex;
        options->subtitlesEnabled = subtitlesEnabled;
        loadSaveSettings();
    }
#endif
    if (gSaveGameEnabled == 0xfe) {
        TitleMenu_ReloadSaveSettings();
        if (gSaveGameEnabled == 0xfe) {
            gSaveGameEnabled = 1;
        }
    }
    if ((gAttractMovieAutoplayEnabled == 0) && (gTitleMenuInputCooldown == 0)) {
        n_attractmode_releaseMovieBuffers();
        loadUiDll(1);
        doNothing_onSaveSelectScreenExit();
        titleScreenDisableActors();
        buttons = mmSetFreeDelay(0);
        mapUnload(0x3d, 0x20000000);
        mmSetFreeDelay(buttons);
        titleDoLoadSave();
        return 0;
    }

    setIsOvercast(0);
    setDrawLights(0);
    if (shouldShowCredits() != 0) {
        return 0;
    }

    if (gTitleMenuInputCooldown != 0) {
        gTitleMenuInputCooldown--;
    }
    if (gAttractMoviePreparePending != 0) {
        n_attractmode_prepareMovie();
    }
    if ((gAttractMovieRetraceCountdown != 0) && (--gAttractMovieRetraceCountdown == 0) &&
        (gAttractMoviePlaybackEnabled != 0)) {
        Movie_SetVolumeFade(NATTRACTMODE_MOVIE_VOLUME_TITLE, NATTRACTMODE_MOVIE_VOLUME_FADE_LONG);
    }
    if ((gAttractMovieState == NATTRACTMODE_MOVIE_STATE_PREPARED) &&
        (++gAttractMovieIdleFrameCount > NATTRACTMODE_MOVIE_RETRACE_COUNTDOWN)) {
        n_attractmode_releaseMovieBuffers();
    }
    if (((gAttractMovieState == NATTRACTMODE_MOVIE_STATE_PREPARED) && (gAttractMoviePlaybackEnabled != 0)) &&
        (gTitleMenuReadyForInput != 0)) {
        buttons = getButtonsJustPressed(0);
        padGetAnalogInput(0, &dpad, &face);
        buttonDisable(0, buttons);
        padClearAnalogInputX(0);
        padClearAnalogInputY(0);

        inputPressed = 0;
        if ((gAttractMovieLoopCompleted != 0) && (gTitleMenuInputCooldown == 0)) {
            inputPressed = 1;
        } else if ((buttons != 0) || ((dpad != 0 || (face != 0)))) {
            inputPressed = 1;
        }
        if (*(u8*)&gAttractMovieLoopCompleted != 0) {
            gAttractMovieLoopCompleted = 0;
        }
        if (inputPressed) {
            if (((buttons != 0) || (dpad != 0)) || (face != 0)) {
                gAttractMovieReplayCountdown = 2;
            } else {
                gAttractMovieReplayCountdown = 1;
                gTitleMenuInputCooldown = TITLE_MENU_ATTRACT_INPUT_COOLDOWN_FRAMES;
            }
            gTitleMenuLinkInterface->vtable->setSelected(0);
            gAttractMoviePlaybackEnabled = 0;
            (*gCameraInterface)->releaseAction((void*)0, 1);
            if (gSaveGameEnabled == 0xff) {
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
                if (loadGameOptions() == 0) {
                    if (OSGetLanguage() == OS_LANGUAGE_DUTCH) {
                        gTitleMenuLanguageSetupState = TITLE_MENU_LANGUAGE_SETUP_REQUESTED;
                    } else if (gSaveGameEnabled != 0) {
                        TitleMenu_CreateSaveFile();
                    }
                }
                loadSaveSettings();
#else
                TitleMenu_ReloadSaveSettings();
#endif
                if (gSaveGameEnabled == 0xff) {
                    gSaveGameEnabled = 1;
                }
            }
        }
    } else if ((gTitleMenuReadyForInput != 0) && (gAttractMoviePlaybackEnabled == 0)) {
        buttons = getButtonsJustPressed(0);
        padGetAnalogInput(0, &dpad, &face);
        if ((buttons != 0) || ((dpad != 0 || (face != 0)))) {
            gAttractMovieReplayCountdown = 2;
        } else if (gAttractMovieLoopCompleted != 0) {
            gAttractMovieLoopCompleted = 0;
            if (gTitleMenuInputCooldown == 0) {
                gTitleMenuInputCooldown = TITLE_MENU_ATTRACT_INPUT_COOLDOWN_FRAMES;
                gAttractMovieReplayCountdown--;
                if (gAttractMovieReplayCountdown == 0) {
                    gAttractMovieReplayCountdown = 1;
                    (*gCameraInterface)->releaseAction((void*)TITLE_MENU_ATTRACT_MOVIE_STATE, 1);
                    gAttractMoviePlaybackEnabled = 1;
                    gTitleMenuSelectionFadeStep = -TITLE_MENU_SELECTION_FADE_STEP;
                }
            }
        }
    }

    if (frames > 3) {
        frames = 3;
    }
    if (gTitleMenuLoadDelay > 0) {
        gTitleMenuLoadDelay -= frames;
    }
    menuId = (*gCameraInterface)->getMode();
    if (menuId != TITLE_MENU_CAMERA_ACTION_ACTIVE) {
        gTitleMenuReadyForInput = 0;
        return 0;
    }

    gTitleMenuReadyForInput = 1;
    if (gTitleMenuNextDllId != 0) {
        if (((previousFadeTimer <= 12) || (gTitleMenuLoadDelay > 12)) && (gTitleMenuLoadDelay <= 0)) {
            gTitleMenuLinkInterface->vtable->free();
            setTitleScreenActive(0);
            setLinkNotRotated();
            loadUiDll(gTitleMenuNextDllId);
        }
        return gTitleMenuLoadDelay <= 12;
    }

    menuId = gTitleMenuLinkInterface->vtable->update();
    gTitleMenuSelection = gTitleMenuLinkInterface->vtable->getSelected();
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
    if (gTitleMenuLanguageSetupState == TITLE_MENU_LANGUAGE_SETUP_REQUESTED) {
        gTitleMenuSelection = 3;
    }
#endif
    if (((1.0f == titleScreenGetCamProgress()) && (gTitleMenuSelectionFade < TITLE_MENU_SELECTION_FADE_MAX)) &&
        (gAttractMoviePlaybackEnabled == 0)) {
        gTitleMenuSelectionFadeStep = TITLE_MENU_SELECTION_FADE_STEP;
        if (gTitleMenuSelection == 0) {
            lbl_803DD618 = 1;
        } else {
            lbl_803DD618 = 0;
        }
    } else if (gTitleMenuPreviousSelection != gTitleMenuSelection) {
        (*gCameraInterface)->releaseAction((void*)gTitleMenuSelection, 1);
        Sfx_PlayFromObject(0, SFXTRIG_menu_fox_select);
        gTitleMenuSelectionFadeStep = -TITLE_MENU_SELECTION_FADE_STEP;
        gTitleMenuPreviousSelection = gTitleMenuSelection;
        Link_setNavigationEnabled(0);
    }
    sum = gTitleMenuSelectionFade + gTitleMenuSelectionFadeStep;
    if (sum >= TITLE_MENU_SELECTION_FADE_MAX) {
        gTitleMenuSelectionFade = TITLE_MENU_SELECTION_FADE_MAX;
        gTitleMenuSelectionFadeStep = 0;
        Link_setNavigationEnabled(1);
    } else if (sum <= 0) {
        TitleMenu_SetEntryHighlight(gTitleMenuSelection);
        gTitleMenuSelectionFade = 0;
        gTitleMenuSelectionFadeStep = 0;
        if (gTitleMenuSelection != 0) {
            lbl_803DD618 = 0;
        }
    } else {
        gTitleMenuSelectionFade += gTitleMenuSelectionFadeStep;
    }
    if (gTitleMenuPanelOpen == 0) {
        if (menuId == 1) {
            gTitleMenuLinkInterface->vtable->free();
            gTitleMenuLinkInterface->vtable->setup(gTitleMenuEntries, 9, 5, NULL, 0, 0, 0x14, 200, 0xff, 0xff, 0xff,
                                                   0xff);
            gTitleMenuPanelOpen = 1;
        }
    } else {
        titleScreenSetMenuSelection(gTitleMenuSelection);
        if ((menuId == 1
#if !defined(VERSION_GSAE01) && !defined(VERSION_GSAJ01)
             || gTitleMenuLanguageSetupState == TITLE_MENU_LANGUAGE_SETUP_REQUESTED
#endif
             ) &&
            (gTitleMenuSelectionFade == TITLE_MENU_SELECTION_FADE_MAX)) {
            titleScreenSetMenuActive(1);
            gTitleMenuLoadDelay = 1;
            Link_setNavigationEnabled(1);
            Sfx_PlayFromObject(0, SFXTRIG_crf_babyflute);
            switch (gTitleMenuSelection) {
            case 0:
                gTitleMenuNextDllId = 5;
                break;
            case 1:
                gTitleMenuNextDllId = 7;
                gOptionsRequestedPanel = 0;
                break;
            case 2:
                gTitleMenuNextDllId = 7;
                gOptionsRequestedPanel = 1;
                break;
            case 3:
                gTitleMenuNextDllId = 7;
                gOptionsRequestedPanel = 2;
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
                if (gTitleMenuLanguageSetupState == TITLE_MENU_LANGUAGE_SETUP_REQUESTED) {
                    gTitleMenuLanguageSetupState = TITLE_MENU_LANGUAGE_SETUP_OPEN;
                }
#endif
                break;
            }
            return 0;
        }
        titleScreenSetMenuActive(0);
    }
    return 0;
}

void TitleMenu_release(void) {
    setLinkNotRotated();
    Link_setNavigationEnabled(1);
    cardSetIdentityCheckEnabled(1);
}

void TitleMenu_setSelection(int selection) {
    u8 v = selection;
    gTitleMenuSelection = v;
    gTitleMenuPreviousSelection = TITLE_MENU_SELECTION_INVALID;
    gTitleMenuLinkInterface->vtable->setSelected(v);
}

void TitleMenu_initialise(void) {
    int i;
    int mode;

    if ((gSaveGameWorkBuffer[0x21] & 0x80) != 0) {
        gAttractMovieAutoplayEnabled = 0;
    } else {
        gAttractMovieAutoplayEnabled = 1;
    }
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
    if (gTitleMenuLanguageSetupState == TITLE_MENU_LANGUAGE_SETUP_OPEN) {
        gTitleMenuLanguageSetupState = TITLE_MENU_LANGUAGE_SETUP_RESTORE;
    }
#endif
    if (gSaveGameEnabled >= 0xfe) {
        cardSetIdentityCheckEnabled(0);
    }
    gameTextLoadDir(0x15);
    gTitleMenuNextDllId = 0;
    gTitleMenuLoadDelay = 0;
    mode = getPrevUiDll();
    if (mode == 3) {
        gTitleMenuLinkInterface->vtable->setup(gTitleMenuClosedPanelEntry, 1, 0, NULL, 0, 0, 0x14, 200, 0xff, 0xff,
                                               0xff, 0xff);
        gTitleMenuPanelOpen = 0;
    } else {
        gTitleMenuLinkInterface->vtable->setup(gTitleMenuEntries, 4, 0, NULL, 0, 0, 0x14, 200, 0xff, 0xff, 0xff, 0xff);
        gTitleMenuPanelOpen = 1;
    }
    gTitleMenuLinkInterface->vtable->setSelected(gTitleMenuSelection);
    titleScreenSetMenuActive(0);

    mode = getPrevUiDll();
    if ((((mode == 0xd) || (mode = getPrevUiDll(), mode == 7)) || (mode = getPrevUiDll(), mode == 6)) ||
        (mode = getPrevUiDll(), mode == 5)) {
        (*gScreenTransitionInterface)->step(0x23, SCREEN_TRANSITION_HUD);
    } else {
        audioStopByMask(0xf);
        (*gScreenTransitionInterface)->step(0x3c, SCREEN_TRANSITION_BLACK);
    }

    setLinkIsRotated();
    for (i = 0; i < 4; i++) {
        if (i == gTitleMenuSelection) {
            gTitleMenuEntries[i].flags &= ~TITLE_MENU_TEXT_ENTRY_HIDDEN;
        } else {
            gTitleMenuEntries[i].flags |= TITLE_MENU_TEXT_ENTRY_HIDDEN;
        }
    }
    gTitleMenuLinkInterface->vtable->copyItems(gTitleMenuEntries);
    gAttractMoviePreparePending = 0;
    gAttractMovieRetraceCountdown = 0;
    gAttractMovieReplayCountdown = 1;
    gTitleMenuInputCooldown = 0x3c;
    gAttractMovieLoopCompleted = 0;

    if ((gAttractMovieAutoplayEnabled != 0) && ((gAttractMovieState == NATTRACTMODE_MOVIE_READY) ||
                                                (gAttractMovieState == NATTRACTMODE_MOVIE_STATE_RELEASED))) {
        n_attractmode_prepareMovie();
        titleScreenPositionElements(-380.0f, 254.0f);
        gAttractMoviePlaybackEnabled = 1;
        Movie_SetVolumeFade(NATTRACTMODE_MOVIE_VOLUME_MUTED, 0);
        audioSetVolumes(0, 10, 1, 0, 0);
        gTitleMenuSelectionFade = 0;
    } else {
        titleScreenPositionElements(-380.0f, 254.0f);
        gAttractMoviePlaybackEnabled = 0;
        Movie_SetVolumeFade(NATTRACTMODE_MOVIE_VOLUME_MUTED, NATTRACTMODE_MOVIE_VOLUME_FADE_IMMEDIATE);
    }
    setIsOvercast(0);
    setDrawLights(0);
    gTitleMenuReadyForInput = 0;
    skySetEnvFxFlags(0);
    gameTimerStop();
    Sfx_SetObjectReverbPreset(0);
    gAttractMovieIdleFrameCount = 0;
}
