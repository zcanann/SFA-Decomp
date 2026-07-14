/*
 * uicontroller (DLL 0x10) - the game's top-level UI frame driver.
 *
 * A thin shim over the shared GameUIInterface vtable (gGameUIInterface):
 * frameStart/frameEnd bracket the per-frame UI pass, and render advances
 * the on-screen game timer (gameTimerRun) when it is running and refreshes
 * the HUD number readout before forwarding to the interface's render.
 * release/initialise are the DLL load/unload hooks (no-ops here).
 */
#include "main/game_ui_interface.h"
#include "main/model_engine.h"
#include "main/dll/dll_0010_uicontroller.h"

#pragma scheduling off
#pragma peephole off
void UIController_render(void* context, int arg1, int arg2)
{
    if (gameTimerIsRunningContext(context, arg1, arg2) != 0)
    {
        gameTimerRunContext(context);
    }
    hudNumberRunContext(context);
    (*gGameUIInterface)->render(context, arg1, arg2);
}

void UIController_frameEnd(void)
{
    (*gGameUIInterface)->frameEnd();
}

void UIController_frameStart(void)
{
    (*gGameUIInterface)->frameStart();
}

void UIController_release(void)
{
}

void UIController_initialise(void)
{
}

u32 lbl_803114B0[10] = {
    0, 0, 0, 0x00050000,
    (u32)UIController_initialise, (u32)UIController_release, 0, (u32)UIController_frameStart,
    (u32)UIController_frameEnd, (u32)UIController_render,
};
