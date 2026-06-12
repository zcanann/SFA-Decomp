/* DLL 0x0033 (nrareware) — Rareware logo / loading screen front-end [0x80115F20-0x8011611C). */
#include "main/dll/FRONT/dll_0032_n_rareware.h"



extern int lbl_803DD5F8;
extern f32 lbl_803DD600;
extern f32 lbl_803DD604;
extern u8 lbl_803DD608;
extern f32 lbl_803E1D08;
extern f32 lbl_803E1D0C;


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
#include "main/screen_transition.h"

extern void Movie_SetVolumeFade(int volume, int fadeFrames);
extern void fn_8001404C(int param_1);
extern void loadUiDll(int id);
extern void GameBit_Set(int eventId, int value);

static char sNRarewareReportTag[] = "n_rareware\n";

extern void OSReport(const char* fmt, ...);

extern u8 framesThisStep;
extern f32 timeDelta;
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern u8 lbl_803DD60A;

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

/* Trivial 4b 0-arg blr leaves. */
