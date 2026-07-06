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

extern u8 gameTimerIsRunning(void* context, int arg1, int arg2);
extern void hudNumberFn_80014060(void* p);
extern void gameTimerRun(void* p);

#pragma scheduling off
#pragma peephole off
void UIController_render(void* context, int arg1, int arg2)
{
    if (gameTimerIsRunning(context, arg1, arg2) != 0)
    {
        gameTimerRun(context);
    }
    hudNumberFn_80014060(context);
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
