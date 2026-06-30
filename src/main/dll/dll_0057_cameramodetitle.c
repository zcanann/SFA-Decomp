/*
 * DLL 0x0057 - CameraModeTitle: the title-screen camera.
 *
 * Holds the camera on one of a fixed table of authored poses (gCamTitlePoseTable,
 * pose index 4 = the resting title pose). moveCam latches the previous pose
 * and starts a transition; update eases the camera from the saved start pose
 * (gCamTitleStartPose) to the target pose over titleScreenCamProgress, applying an
 * ease curve and shortest-arc angle interpolation on each of yaw/pitch/roll.
 * Entering or leaving pose 4 cross-fades the title music tracks and the movie
 * volume against the saved-file music-volume byte (save[10]).
 *
 * Also hosts the shared no-op release/free/copy callbacks the sibling
 * camera-mode DLLs reference. The trailing comments document the v1.0
 * curve/movement helpers that live in the wider camera-mode address range.
 */
#include "main/dll/cameramodetitlepose_struct.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/dll/gameplay.h"
#include "main/dll/FRONT/n_options.h"
#include "main/dll/dll_80220608_shared.h"

#pragma scheduling on
#pragma peephole on

/* title-screen music tracks crossfaded as pose 4 is entered/left */
#define MUSIC_TITLE_TRACK_A 0xbe
#define MUSIC_TITLE_TRACK_B 0xc1

/* gCamTitlePoseTable pose index of the resting title pose */
#define TITLE_CAM_REST_POSE 4

extern void audioSetVolumes(int volume, int p1, int p2, int p3, int p4);
extern CameraModeTitlePose gCamTitlePoseTable[];
extern u8 gCamTitleCurPose;
extern u8 gCamTitlePrevPose;
extern u8 gCamTitleStartPosePending;
extern f32 lbl_803E1BE0;
extern f32 titleScreenCamProgress;
extern CameraModeCloudRunnerState* lbl_803DD5B8;
extern f32 lbl_803E1BE4;

extern CameraModeTitlePose gCamTitleStartPose;
extern f32 gCamTitleProgressStep;
extern f32 lbl_803E1BEC;
extern f32 lbl_803E1BF0;
extern f32 lbl_803E1BF4;
extern f32 lbl_803E1BF8;
extern f32 lbl_803E1BFC;
extern f32 gCamTitleAngleWrapThreshold;

#pragma scheduling off
#pragma peephole off
void CameraModeForceBehind_func06_nop(void)
{
}

void CameraModeForceBehind_func05_nop(void)
{
}

void CameraModeForceBehind_release(void);

void fn_801101E4(void)
{
}

void CameraModeCloudRunner_release(void);

void fn_80110C80(void)
{
}

void CameraModePerv_release(void);

void fn_80110EC0(void)
{
}

void CameraModeArwing_release(void);

void CameraModeTitle_release(void)
{
}

void CameraModeTitle_initialise(void)
{
}

void CameraModeForceBehind_copyToCurrent(void);

void CameraModeTitle_loadVolumes(void)
{
    u8* save = getSaveFileStruct();
    audioSetVolumes(save[10], 1000, 1, 0, 0);
}

void dll_4F_init(void);

#pragma opt_common_subs off
#pragma opt_common_subs reset

void CameraModeTitle_init(CameraObject* camera)
{
    gCamTitleCurPose = TITLE_CAM_REST_POSE;
    gCamTitlePrevPose = TITLE_CAM_REST_POSE;
    titleScreenCamProgress = lbl_803E1BE0;
    gCamTitleStartPosePending = 0;

    camera->anim.localPosX = gCamTitlePoseTable[TITLE_CAM_REST_POSE].x;
    camera->anim.localPosY = gCamTitlePoseTable[gCamTitleCurPose].y;
    camera->anim.localPosZ = gCamTitlePoseTable[gCamTitleCurPose].z;
    camera->anim.rotX = gCamTitlePoseTable[gCamTitleCurPose].yaw;
    camera->anim.rotY = gCamTitlePoseTable[gCamTitleCurPose].pitch;
    camera->anim.rotZ = gCamTitlePoseTable[gCamTitleCurPose].roll;
}

void CameraModeTitle_moveCam(u8 newCam)
{
    u32 cam = newCam;
    if (cam == gCamTitleCurPose) return;
    if (gCamTitlePrevPose == TITLE_CAM_REST_POSE)
    {
        if (lbl_803E1BE0 != titleScreenCamProgress)
        {
            u8* save = getSaveFileStruct();
            Movie_SetVolumeFade(0, 1000);
            audioSetVolumes(save[10], 1000, 1, 0, 0);
        }
        else
        {
            Music_Trigger(MUSIC_TITLE_TRACK_A, 1);
            Music_Trigger(MUSIC_TITLE_TRACK_B, 1);
        }
    }
    gCamTitlePrevPose = gCamTitleCurPose;
    gCamTitleCurPose = cam;
    titleScreenCamProgress = lbl_803E1BE4;
    gCamTitleStartPosePending = 1;
}

f32 titleScreenGetCamProgress(void) { return titleScreenCamProgress; }

void CameraModeWorldMap_free(void);

void fn_801101E8(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)lbl_803DD5B8);
    lbl_803DD5B8 = NULL;
}

void CameraModeCloudRunner_free(void);

#pragma dont_inline on
#pragma dont_inline reset

void CameraModeTitle_update(CameraObject* camera)
{
    if (gCamTitleStartPosePending != 0)
    {
        gCamTitleStartPose.x = camera->anim.localPosX;
        gCamTitleStartPose.y = camera->anim.localPosY;
        gCamTitleStartPose.z = camera->anim.localPosZ;
        gCamTitleStartPose.yaw = camera->anim.rotX;
        gCamTitleStartPose.pitch = camera->anim.rotY;
        gCamTitleStartPose.roll = camera->anim.rotZ;
        gCamTitleStartPosePending = 0;
    }
    if (gCamTitleCurPose != gCamTitlePrevPose)
    {
        u8* save = getSaveFileStruct();
        f32 v;

        titleScreenCamProgress = titleScreenCamProgress + gCamTitleProgressStep;
        if (titleScreenCamProgress >= lbl_803E1BE0)
        {
            if (gCamTitleCurPose == TITLE_CAM_REST_POSE)
            {
                Movie_SetVolumeFade(100, 1);
                audioSetVolumes(0, 10, 1, 0, 0);
                Music_Trigger(MUSIC_TITLE_TRACK_A, 0);
                Music_Trigger(MUSIC_TITLE_TRACK_B, 0);
            }
            else if (gCamTitlePrevPose == TITLE_CAM_REST_POSE)
            {
                Movie_SetVolumeFade(0, 1);
                audioSetVolumes(save[10], 10, 1, 0, 0);
            }
            titleScreenCamProgress = lbl_803E1BE0;
            gCamTitlePrevPose = gCamTitleCurPose;
        }
        else
        {
            if (gCamTitleCurPose == TITLE_CAM_REST_POSE)
            {
                Movie_SetVolumeFade((s32)(lbl_803E1BEC * titleScreenCamProgress), 1);
                audioSetVolumes(
                    (s32)((f32)(u32)save[10] * (lbl_803E1BE0 - titleScreenCamProgress)), 10, 1, 0,
                    0);
            }
            else if (gCamTitlePrevPose == TITLE_CAM_REST_POSE)
            {
                Movie_SetVolumeFade((s32)(lbl_803E1BEC * (lbl_803E1BE0 - titleScreenCamProgress)), 1);
                audioSetVolumes((s32)((f32)(u32)save[10] * titleScreenCamProgress), 10, 1, 0, 0);
            }
        }

        if (titleScreenCamProgress < *(f32*)&lbl_803E1BF0)
        {
            v = lbl_803E1BF0 *
                ((lbl_803E1BF4 * titleScreenCamProgress) * (lbl_803E1BF4 * titleScreenCamProgress));
        }
        else
        {
            f32 w = -(lbl_803E1BF4 * (titleScreenCamProgress - lbl_803E1BF0) - lbl_803E1BE0);
            w = w * w;
            v = lbl_803E1BF0 * (lbl_803E1BE0 - w) + lbl_803E1BF0;
        }
        v = v * ((lbl_803E1BFC * v) * v) + (lbl_803E1BF0 * v + (lbl_803E1BF8 * v) * v);

        camera->anim.localPosX =
            v * (gCamTitlePoseTable[gCamTitleCurPose].x - gCamTitleStartPose.x) + gCamTitleStartPose.x;
        camera->anim.localPosY =
            v * (gCamTitlePoseTable[gCamTitleCurPose].y - gCamTitleStartPose.y) + gCamTitleStartPose.y;
        camera->anim.localPosZ =
            v * (gCamTitlePoseTable[gCamTitleCurPose].z - gCamTitleStartPose.z) + gCamTitleStartPose.z;

        {
            u16 sy = gCamTitleStartPose.yaw;
            int d = gCamTitlePoseTable[gCamTitleCurPose].yaw - sy;
            if (__fabs((f32)d) > gCamTitleAngleWrapThreshold)
            {
                int d2 = (s16)gCamTitlePoseTable[gCamTitleCurPose].yaw - (s16)sy;
                camera->anim.rotX = (s16)(s32)(v * d2 + (f32)(s16)sy);
            }
            else
            {
                *(u16*)&camera->anim.rotX = v * d + sy;
            }
        }
        {
            u16 sy = gCamTitleStartPose.pitch;
            int d = gCamTitlePoseTable[gCamTitleCurPose].pitch - sy;
            if (__fabs((f32)d) > gCamTitleAngleWrapThreshold)
            {
                int d2 = (s16)gCamTitlePoseTable[gCamTitleCurPose].pitch - (s16)sy;
                camera->anim.rotY = (s16)(s32)(v * d2 + (f32)(s16)sy);
            }
            else
            {
                *(u16*)&camera->anim.rotY = v * d + sy;
            }
        }
        {
            u16 sy = gCamTitleStartPose.roll;
            int d = gCamTitlePoseTable[gCamTitleCurPose].roll - sy;
            if (__fabs((f32)d) > gCamTitleAngleWrapThreshold)
            {
                int d2 = (s16)gCamTitlePoseTable[gCamTitleCurPose].roll - (s16)sy;
                camera->anim.rotZ = (s16)(s32)(v * d2 + (f32)(s16)sy);
            }
            else
            {
                *(u16*)&camera->anim.rotZ = v * d + sy;
            }
        }
    }
}

/* EN v1.0 0x80114184  size: 160b  Copies a curve point's position and packed
 * angle into the caller's record. */

/* EN v1.0 0x80114084  size: 256b  Copies a curve point's position into the
 * caller's record and aims its angle at the nearest group-8 object (falling
 * back to the point's packed angle). */

/* EN v1.0 0x80113864  size: 248b  Steps the movement blend factors toward the
 * current target and turns the yaw by the buffered turn rate. */

/* EN v1.0 0x80114F64  size: 280b  Initializes the movement-state block and
 * primes the animation channel tables. */

/* EN v1.0 0x80114DEC  size: 376b  Latches the path-relative start offset on
 * first use and refreshes the current path point position. */

/* EN v1.0 0x80113BD0  size: 396b  Computes the yaw step, signed yaw delta and
 * distance from an object to its target, updating the wide-turn flag. */

/* EN v1.0 0x80113D64  size: 544b  Probes the four compass directions around
 * the object for walkable space, returning a bitmask of clear directions. */

/* EN v1.0 0x801145BC  size: 512b  Advances the object along its movement
 * curve, snapping to ground and easing the yaw toward the path direction. */

/* EN v1.0 0x80114BB0  size: 572b  Object-sequence scripted-move step: phase 4
 * arms the move, phase 5 walks the setup/playback sub-phases. */

/* EN v1.0 0x8011395C  size: 628b  Constrains a follow point against the
 * object's facing plane and returns the lateral offset of the result. */

/* EN v1.0 0x801147BC  size: 864b  Homes the object toward its target at the
 * given speed, snapping when close, easing yaw and pacing the walk anim. */
