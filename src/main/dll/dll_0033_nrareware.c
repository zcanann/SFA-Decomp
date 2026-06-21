/* DLL 0x0033 (nrareware) — Rareware logo / loading screen front-end [0x80115F20-0x8011611C). */
#include "main/screen_transition.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"
extern int gNrarewareFrameCounter;
extern f32 gNrarewareStage3Timer;
extern f32 gNrarewareStage1Timer;
extern u8 gNrarewareTransitionStarted;
extern f32 lbl_803E1D08;
extern f32 lbl_803E1D0C;
extern void fn_8001404C(int value);
extern void OSReport(const char* msg, ...);
extern u8 framesThisStep;
extern f32 timeDelta;
extern u8 gNrarewareTimeoutFlag;

void n_rareware_render(void)
{
    extern u8 gNrarewareExitDelay; /* #57 */
    extern u8 gNrarewareStage; /* #57 */
    int frame;

    if (((s8)gNrarewareTransitionStarted != 0) && ((s8)gNrarewareExitDelay <= 10))
    {
        return;
    }

    frame = gNrarewareFrameCounter;
    if ((frame > 40) && ((s8)gNrarewareStage == 0))
    {
        gNrarewareStage = 1;
        gNrarewareStage1Timer = lbl_803E1D08;
    }
    if ((frame > 50) && ((s8)gNrarewareStage == 1))
    {
        gNrarewareStage = 2;
    }
    if ((frame > 285) && ((s8)gNrarewareStage == 2))
    {
        gNrarewareStage = 3;
        gNrarewareStage3Timer = lbl_803E1D0C;
    }
}

void n_rareware_frameEnd(void)
{
}

static char sNRarewareReportTag[] = "n_rareware\n";

int n_rareware_frameStart(void)
{
    extern s8 gNrarewareExitDelay; /* #57 */
    extern s8 gNrarewareStage; /* #57 */
    int frameStep;

    frameStep = framesThisStep;
    OSReport(sNRarewareReportTag);
    if (frameStep > 3)
    {
        frameStep = 3;
    }
    if ((s8)gNrarewareExitDelay > 0)
    {
        gNrarewareExitDelay = (s8)(gNrarewareExitDelay - frameStep);
    }
    if ((s8)gNrarewareTransitionStarted != 0)
    {
        GameBit_Set(0x44f, 0);
        loadUiDll(4);
    }
    gNrarewareFrameCounter += framesThisStep;
    if (gNrarewareFrameCounter > 0x26c)
    {
        gNrarewareTimeoutFlag = 1;
    }
    if ((s8)gNrarewareTimeoutFlag != 0)
    {
        (*gScreenTransitionInterface)->start(0x1e, 1);
        gNrarewareExitDelay = 0x2d;
        gNrarewareTransitionStarted = 1;
    }
    if (gNrarewareStage > 0)
    {
        gNrarewareStage1Timer -= timeDelta;
    }
    if (gNrarewareStage > 2)
    {
        gNrarewareStage3Timer -= timeDelta;
    }
    return 0;
}

void n_rareware_release(void)
{
}

void n_rareware_initialise(void)
{
    extern s8 gNrarewareExitDelay; /* #57 */
    extern s8 gNrarewareStage; /* #57 */
    fn_8001404C(0);
    gNrarewareFrameCounter = 0;
    gNrarewareStage = 0;
    gNrarewareTimeoutFlag = 0;
    gNrarewareExitDelay = 0;
    gNrarewareTransitionStarted = 0;
}
