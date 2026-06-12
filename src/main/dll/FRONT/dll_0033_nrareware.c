/* === moved from main/dll/FRONT/n_rareware.c [80115F20-80115FBC) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/FRONT/n_rareware.h"



extern int lbl_803DD5F8;
extern f32 lbl_803DD600;
extern f32 lbl_803DD604;
extern u8 lbl_803DD608;
extern f32 lbl_803E1D08;
extern f32 lbl_803E1D0C;

typedef struct LoadingScreenTexture
{
    undefined _00[0xa];
    u16 width;
    u16 height;
    u16 unk0e;
    u16 unk10;
    undefined _12[4];
    u8 format;
    u8 wrapS;
    u8 wrapT;
    u8 minFilter;
    u8 magFilter;
    undefined _1b[5];
    u32 texObj[8];
    int unk40;
    uint bufferSize;
    u8 unk48;
    undefined _49[0x17];
    u8 imageData[1];
} LoadingScreenTexture;

/*
 * --INFO--
 *
 * Function: runLoadingScreens
 * EN v1.0 Address: 0x801159E4
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x80115C80
 * EN v1.1 Size: 880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: initLoadingScreenTextures
 * EN v1.0 Address: 0x80115D54
 * EN v1.0 Size: 280b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* Trivial 4b 0-arg blr leaves. */


/*
 * --INFO--
 *
 * Function: TitleScreenInit_frameStart
 * EN v1.0 Address: 0x80115E74
 * EN v1.0 Size: 72b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: TitleScreenInit_initialise
 * EN v1.0 Address: 0x80115EC0
 * EN v1.0 Size: 96b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: n_rareware_render
 * EN v1.0 Address: 0x80115F20
 * EN v1.0 Size: 152b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void n_rareware_render(void)
{
    extern u8 lbl_803DD609; /* #57 */
    extern u8 lbl_803DD5FC; /* #57 */
    int frame;

    if (((s8)lbl_803DD608 != 0) && ((s8)lbl_803DD609 <= 10))
    {
        return;
    }

    frame = lbl_803DD5F8;
    if ((frame > 40) && ((s8)lbl_803DD5FC == 0))
    {
        lbl_803DD5FC = 1;
        lbl_803DD604 = lbl_803E1D08;
    }
    if ((frame > 50) && ((s8)lbl_803DD5FC == 1))
    {
        lbl_803DD5FC = 2;
    }
    if ((frame > 285) && ((s8)lbl_803DD5FC == 2))
    {
        lbl_803DD5FC = 3;
        lbl_803DD600 = lbl_803E1D0C;
    }
}

void n_rareware_frameEnd(void)
{
}

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
extern f32 lbl_803DD600;
extern f32 lbl_803DD604;
extern u8 lbl_803DD608;
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
    extern s8 lbl_803DD609; /* #57 */
    extern s8 lbl_803DD5FC; /* #57 */
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
    extern s8 lbl_803DD609; /* #57 */
    extern s8 lbl_803DD5FC; /* #57 */
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
#pragma dont_inline on
void n_attractmode_releaseMovieBuffers(void);

#pragma dont_inline reset

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
void n_attractmode_prepareMovie(void);

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
void TitleMenu_render(u8* param_1);

/* Trivial 4b 0-arg blr leaves. */
void TitleMenu_frameEnd(void);
