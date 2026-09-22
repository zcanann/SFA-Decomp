#include "dolphin/os.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "dlls/object_descriptor.h"
#include "main/dll/tricky.h"
#include "main/map_load.h"
#include "main/model_engine.h"
#include "main/rcp_dolphin_api.h"
#include "main/sky.h"
#include "main/dll/FRONT/dll_0032_titlescreeninit.h"

f32 lbl_803DD5F4;
s8 gTitleScreenInitFrameStartPending;

#define TITLESCREENINIT_MAP_PRIOR 0x3d
#define TITLESCREENINIT_MAP_TITLE 0x3f
#define TITLESCREENINIT_MAP_WARP  0x12

void TitleScreenInit_render(void)
{
}

void TitleScreenInit_frameEnd(void)
{
}

int TitleScreenInit_frameStart(void)
{
    if (gTitleScreenInitFrameStartPending != 0)
    {
        gTitleScreenInitFrameStartPending = 0;
        lbl_803DD5F4 = 0.0f;
        loadUiDll(4);
    }
    return 0;
}

void TitleScreenInit_release(void)
{
}

void TitleScreenInit_initialise(void)
{
    gTitleScreenInitFrameStartPending = 1;
    lbl_803DD5F4 = 0.0f;
    mapUnload(TITLESCREENINIT_MAP_PRIOR, 0x10000000);
    setForceLoadImmediately();
    loadMapAndParent(TITLESCREENINIT_MAP_TITLE);
    clearForceLoadImmediately();
    loadSunAndMoon();
    gameUiLoadResources();
    camcontrol_initialiseTargetReticle();
    warpToMap(TITLESCREENINIT_MAP_WARP, 0);
}

ObjectDescriptor6 TitleScreenInit_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)TitleScreenInit_initialise,
    (ObjectDescriptorCallback)TitleScreenInit_release,
    0,
    (ObjectDescriptorCallback)TitleScreenInit_frameStart,
    (ObjectDescriptorCallback)TitleScreenInit_frameEnd,
    (ObjectDescriptorCallback)TitleScreenInit_render,
};
