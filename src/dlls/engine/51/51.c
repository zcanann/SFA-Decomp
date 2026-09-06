#include "main/dll/FRONT/dll_0033_n_rareware.h"
#include "dolphin/os/OSReport.h"
#include "main/screen_transition.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/dll/FRONT/dll_39.h"
#include "dlls/object_descriptor.h"
#include "main/model_engine.h"

u8 gNrarewareTimeoutFlag;
s8 gNrarewareExitDelay;
u8 gNrarewareTransitionStarted;
f32 gNrarewareStage1Timer;
f32 gNrarewareStage3Timer;
s8 gNrarewareStage;
int gNrarewareFrameCounter;

void n_rareware_render(void)
{
    int frame;

    if (((s8)gNrarewareTransitionStarted != 0) && (gNrarewareExitDelay <= 10))
    {
        return;
    }

    frame = gNrarewareFrameCounter;
    if ((frame > 40) && (gNrarewareStage == 0))
    {
        gNrarewareStage = 1;
        gNrarewareStage1Timer = 5e+02f;
    }
    if ((frame > 50) && (gNrarewareStage == 1))
    {
        gNrarewareStage = 2;
    }
    if ((frame > 285) && (gNrarewareStage == 2))
    {
        gNrarewareStage = 3;
        gNrarewareStage3Timer = 145.0f;
    }
}

void n_rareware_frameEnd(void)
{
}

ObjectDescriptor6 n_rareware_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)n_rareware_initialise,
    (ObjectDescriptorCallback)n_rareware_release,
    0,
    (ObjectDescriptorCallback)n_rareware_frameStart,
    (ObjectDescriptorCallback)n_rareware_frameEnd,
    (ObjectDescriptorCallback)n_rareware_render,
};

static char sNRarewareReportTag[] = "n_rareware\n";

int n_rareware_frameStart(void)
{
    int frameStep;

    frameStep = framesThisStep;
    OSReport(sNRarewareReportTag);
    if (frameStep > 3)
    {
        frameStep = 3;
    }
    if (gNrarewareExitDelay > 0)
    {
        gNrarewareExitDelay -= frameStep;
    }
    if ((s8)gNrarewareTransitionStarted != 0)
    {
        mainSetBits(GAMEBIT_MenuRelated044F, 0);
        loadUiDll(4);
    }
    gNrarewareFrameCounter += framesThisStep;
    if (gNrarewareFrameCounter > 0x26c)
    {
        gNrarewareTimeoutFlag = 1;
    }
    if ((s8)gNrarewareTimeoutFlag != 0)
    {
        (*gScreenTransitionInterface)->start(0x1e, SCREEN_TRANSITION_BLACK);
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
    menuSetState(0);
    gNrarewareFrameCounter = 0;
    gNrarewareStage = 0;
    gNrarewareTimeoutFlag = 0;
    gNrarewareExitDelay = 0;
    gNrarewareTransitionStarted = 0;
}
