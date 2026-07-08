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

extern void camcontrol_queueSavedAction(void);
extern void Camera_func1D(void);
extern void Camera_func1C(void);
extern void Camera_getMinimapInfoText(void);
extern void camcontrol_release(void);
extern void Camera_setLetterbox(void);
extern void Camera_minimapShowHelpTextForTarget(void);
extern void camcontrol_updateTargetFeedback(void);
extern void Camera_isZooming(void);
extern void Camera_setTargetReticleOverride(void);
extern void Camera_setTarget(void);
extern void Camera_func13(void);
extern void Camera_getTarget(void);
extern void Camera_getOverrideTarget(void);
extern void camcontrol_getRelativePosition(void);
extern void camcontrol_initialise(void);
extern void Camera_moveBy(void);
extern void Camera_overridePos(void);
extern void Camera_setFocus(void);
extern void camcontrol_loadTriggeredCamAction(void);
extern void Camera_getCamActionsBinEntry(void);
extern void Camera_setMode(void);
extern void Camera_getDefaultHandlerEntry(void);
extern void Camera_GetFollowPos(void);
extern void Camera_getMode(void);
extern void Camera_get(void);
extern void Camera_update(void);
extern void Camera_init(void);
extern void Camera_release(void);
extern void Camera_initialise(void);

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

/* Explicit length 40 (string data is 36 bytes; NUL-fill supplies the 4-byte
 * retail pad gap_07_80319A84_data) so the 35-word descriptor table below
 * starts 8-aligned at +0x28 as in retail. The u64-union idiom used by the
 * 8-word tables (dll_00AD/dll_000A) can't be used here: MWCC rounds the
 * union's size up to 0x90, adding 4 trailing bytes retail doesn't have. */
char sProjdfp1rDoNoLongerSupported[40] = "<projdfp1r Do>No Longer supported \n";

/* descriptor/ptr table auto 0x80319a88-0x80319b14 (8-byte aligned in retail;
 * pointer tables regenerate ADDR32 relocs) */
void* lbl_80319A88[35] = {(void*)0x00000000,
                          (void*)0x00000000,
                          (void*)0x00000000,
                          (void*)0x001d0000,
                          Camera_initialise,
                          Camera_release,
                          (void*)0x00000000,
                          Camera_init,
                          Camera_update,
                          Camera_get,
                          Camera_getMode,
                          Camera_GetFollowPos,
                          Camera_getDefaultHandlerEntry,
                          Camera_setMode,
                          Camera_getCamActionsBinEntry,
                          camcontrol_loadTriggeredCamAction,
                          Camera_setFocus,
                          Camera_overridePos,
                          Camera_moveBy,
                          camcontrol_initialise,
                          camcontrol_getRelativePosition,
                          Camera_getOverrideTarget,
                          Camera_getTarget,
                          Camera_func13,
                          Camera_setTarget,
                          Camera_setTargetReticleOverride,
                          Camera_isZooming,
                          camcontrol_updateTargetFeedback,
                          Camera_minimapShowHelpTextForTarget,
                          Camera_setLetterbox,
                          camcontrol_release,
                          Camera_getMinimapInfoText,
                          Camera_func1C,
                          Camera_func1D,
                          camcontrol_queueSavedAction};
