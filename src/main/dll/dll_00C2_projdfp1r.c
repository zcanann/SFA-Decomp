/*
 * projdfp1r (DLL 0xC2) - retired "dfp1r" projectile object.
 *
 * The object is no longer supported: its single behavior entry point just
 * prints the "projdfp1r ... No Longer supported" banner and returns -1, and
 * the load/unload hooks are empty stubs.
 */
#include "dolphin/os.h"
#include "main/dll/dll_89.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

int projdfp1r_doUnsupported(void)
{
    OSReport(sProjdfp1rDoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projdfp1r_release(void)
{
}

void projdfp1r_initialise(void)
{
}

char sProjdfp1rDoNoLongerSupported[] = "<projdfp1r Do>No Longer supported \n";

/* descriptor/ptr table auto 0x80319a88-0x80319b14 */
u32 lbl_80319A88[35] = { 0x00000000, 0x00000000, 0x00000000, 0x001d0000, (u32)Camera_initialise, (u32)Camera_release, 0x00000000, (u32)Camera_init, (u32)Camera_update, (u32)Camera_get, (u32)Camera_getMode, (u32)Camera_GetFollowPos, (u32)Camera_getDefaultHandlerEntry, (u32)Camera_setMode, (u32)Camera_getCamActionsBinEntry, (u32)camcontrol_loadTriggeredCamAction, (u32)Camera_setFocus, (u32)Camera_overridePos, (u32)Camera_moveBy, (u32)camcontrol_initialise, (u32)camcontrol_getRelativePosition, (u32)Camera_getOverrideTarget, (u32)Camera_getTarget, (u32)Camera_func13, (u32)Camera_setTarget, (u32)Camera_setTargetReticleOverride, (u32)Camera_isZooming, (u32)camcontrol_updateTargetFeedback, (u32)Camera_minimapShowHelpTextForTarget, (u32)Camera_setLetterbox, (u32)camcontrol_release, (u32)Camera_getMinimapInfoText, (u32)Camera_func1C, (u32)Camera_func1D, (u32)camcontrol_queueSavedAction };
