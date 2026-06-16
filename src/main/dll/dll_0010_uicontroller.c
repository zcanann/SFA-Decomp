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

extern u8 gameTimerIsRunning(void* p, int a, int b);
extern void hudNumberFn_80014060(void* p);
extern void gameTimerRun(void* p);

#pragma scheduling off
#pragma peephole off
void UIController_render(void* p, int a, int b)
{
    if (gameTimerIsRunning(p, a, b) != 0)
    {
        gameTimerRun(p);
    }
    hudNumberFn_80014060(p);
    (*gGameUIInterface)->render(p, a, b);
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
