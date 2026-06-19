/* DLL 0x0033 (nrareware) — Rareware logo / loading screen front-end [0x80115F20-0x8011611C). */
#include "main/screen_transition.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"

extern int lbl_803DD5F8;
extern f32 lbl_803DD600;
extern f32 lbl_803DD604;
extern u8 lbl_803DD608;
extern f32 lbl_803E1D08;
extern f32 lbl_803E1D0C;

extern void fn_8001404C(int param_1);


extern void OSReport(const char* msg, ...);
extern u8 framesThisStep;
extern f32 timeDelta;
extern u8 lbl_803DD60A;

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

static char sNRarewareReportTag[] = "n_rareware\n";

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
