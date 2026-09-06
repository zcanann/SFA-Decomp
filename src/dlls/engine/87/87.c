/*
 * DLL 87 / 0x57 - the title-screen camera.
 *
 * Holds the camera on one of a fixed table of authored poses
 * (gCameraModeTitlePoseTable, pose index 4 = the resting title pose). moveCam
 * latches the previous pose and starts a transition; update eases the camera
 * from the saved start pose (gCameraModeTitleStartPose) to the target pose over
 * gCameraModeTitleProgress, applying an ease curve and shortest-arc angle
 * interpolation on each of yaw/pitch/roll.
 * Entering or leaving pose 4 cross-fades the title music tracks and the movie
 * volume against the saved-file music-volume setting.
 */
#include "main/dll/dll_0057_cameramodetitle.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/attract_movie_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/dll_0015_save_settings.h"

u8 gCameraModeTitleCurrentPose;
u8 gCameraModeTitlePreviousPose;
u8 gCameraModeTitleStartPosePending;

f32 gCameraModeTitleProgress = 1.0f;

CameraModeTitlePose gCameraModeTitleStartPose;

f32 titleScreenGetCamProgress(void) {
    return gCameraModeTitleProgress;
}

void CameraModeTitle_moveCam(u8 newPose) {
    u32 pose = newPose;
    if (pose == gCameraModeTitleCurrentPose) {
        return;
    }
    if (gCameraModeTitlePreviousPose == CAMERA_MODE_TITLE_REST_POSE) {
        if (gCameraModeTitleProgress != 1.0f) {
            SaveData* save = getSaveFileStruct();
            Movie_SetVolumeFade(0, 1000);
            audioSetVolumes(save->musicVolume, 1000, 1, 0, 0);
        } else {
            Music_Trigger(MUSICTRIG_cldrnr_tune1_be, 1);
            Music_Trigger(MUSICTRIG_windydocks, 1);
        }
    }
    gCameraModeTitlePreviousPose = gCameraModeTitleCurrentPose;
    gCameraModeTitleCurrentPose = pose;
    gCameraModeTitleProgress = 0.0f;
    gCameraModeTitleStartPosePending = 1;
}

void CameraModeTitle_loadVolumes(void) {
    SaveData* save = getSaveFileStruct();
    audioSetVolumes(save->musicVolume, 1000, 1, 0, 0);
}

void CameraModeTitle_update(CameraObject* camera) {
    if (gCameraModeTitleStartPosePending != 0) {
        gCameraModeTitleStartPose.x = camera->anim.localPosX;
        gCameraModeTitleStartPose.y = camera->anim.localPosY;
        gCameraModeTitleStartPose.z = camera->anim.localPosZ;
        gCameraModeTitleStartPose.yaw = camera->anim.rotX;
        gCameraModeTitleStartPose.pitch = camera->anim.rotY;
        gCameraModeTitleStartPose.roll = camera->anim.rotZ;
        gCameraModeTitleStartPosePending = 0;
    }
    if (gCameraModeTitleCurrentPose != gCameraModeTitlePreviousPose) {
        SaveData* save = getSaveFileStruct();
        f32 ease;

        gCameraModeTitleProgress += 0.01f;
        if (gCameraModeTitleProgress >= 1.0f) {
            if (gCameraModeTitleCurrentPose == CAMERA_MODE_TITLE_REST_POSE) {
                Movie_SetVolumeFade(100, 1);
                audioSetVolumes(0, 10, 1, 0, 0);
                Music_Trigger(MUSICTRIG_cldrnr_tune1_be, 0);
                Music_Trigger(MUSICTRIG_windydocks, 0);
            } else if (gCameraModeTitlePreviousPose == CAMERA_MODE_TITLE_REST_POSE) {
                Movie_SetVolumeFade(0, 1);
                audioSetVolumes(save->musicVolume, 10, 1, 0, 0);
            }
            gCameraModeTitleProgress = 1.0f;
            gCameraModeTitlePreviousPose = gCameraModeTitleCurrentPose;
        } else {
            if (gCameraModeTitleCurrentPose == CAMERA_MODE_TITLE_REST_POSE) {
                Movie_SetVolumeFade((s32)(100.0f * gCameraModeTitleProgress), 1);
                audioSetVolumes((s32)((f32)(u32)save->musicVolume * (1.0f - gCameraModeTitleProgress)), 10, 1, 0, 0);
            } else if (gCameraModeTitlePreviousPose == CAMERA_MODE_TITLE_REST_POSE) {
                Movie_SetVolumeFade((s32)(100.0f * (1.0f - gCameraModeTitleProgress)), 1);
                audioSetVolumes((s32)((f32)(u32)save->musicVolume * gCameraModeTitleProgress), 10, 1, 0, 0);
            }
        }

        if (gCameraModeTitleProgress < 0.5f) {
            ease = 0.5f * ((2.0f * gCameraModeTitleProgress) * (2.0f * gCameraModeTitleProgress));
        } else {
            f32 inverseEase = -(2.0f * (gCameraModeTitleProgress - 0.5f) - 1.0f);
            inverseEase *= inverseEase;
            ease = (1.0f - inverseEase) * 0.5f + 0.5f;
        }
        ease = (0.5f * ease + (1.5f * ease) * ease) + ease * ((-1.0f * ease) * ease);

        camera->anim.localPosX =
            ease * (gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].x - gCameraModeTitleStartPose.x) +
            gCameraModeTitleStartPose.x;
        camera->anim.localPosY =
            ease * (gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].y - gCameraModeTitleStartPose.y) +
            gCameraModeTitleStartPose.y;
        camera->anim.localPosZ =
            ease * (gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].z - gCameraModeTitleStartPose.z) +
            gCameraModeTitleStartPose.z;

        {
            u16 startAngle = gCameraModeTitleStartPose.yaw;
            int angleDelta = gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].yaw - startAngle;
            if (__fabsf((f32)angleDelta) > 32767.0f) {
                int wrappedDelta = (s16)gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].yaw - (s16)startAngle;
                camera->anim.rotX = (s16)(s32)(ease * wrappedDelta + (f32)(s16)startAngle);
            } else {
                camera->anim.rotX = ease * angleDelta + startAngle;
            }
        }
        {
            u16 startAngle = gCameraModeTitleStartPose.pitch;
            int angleDelta = gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].pitch - startAngle;
            if (__fabsf((f32)angleDelta) > 32767.0f) {
                int wrappedDelta = (s16)gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].pitch - (s16)startAngle;
                camera->anim.rotY = (s16)(s32)(ease * wrappedDelta + (f32)(s16)startAngle);
            } else {
                camera->anim.rotY = ease * angleDelta + startAngle;
            }
        }
        {
            u16 startAngle = gCameraModeTitleStartPose.roll;
            int angleDelta = gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].roll - startAngle;
            if (__fabsf((f32)angleDelta) > 32767.0f) {
                int wrappedDelta = (s16)gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].roll - (s16)startAngle;
                camera->anim.rotZ = (s16)(s32)(ease * wrappedDelta + (f32)(s16)startAngle);
            } else {
                camera->anim.rotZ = ease * angleDelta + startAngle;
            }
        }
    }
}

void CameraModeTitle_init(CameraObject* camera) {
    gCameraModeTitleCurrentPose = CAMERA_MODE_TITLE_REST_POSE;
    gCameraModeTitlePreviousPose = CAMERA_MODE_TITLE_REST_POSE;
    gCameraModeTitleProgress = 1.0f;
    gCameraModeTitleStartPosePending = 0;

    camera->anim.localPosX = gCameraModeTitlePoseTable[CAMERA_MODE_TITLE_REST_POSE].x;
    camera->anim.localPosY = gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].y;
    camera->anim.localPosZ = gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].z;
    camera->anim.rotX = gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].yaw;
    camera->anim.rotY = gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].pitch;
    camera->anim.rotZ = gCameraModeTitlePoseTable[gCameraModeTitleCurrentPose].roll;
}

void CameraModeTitle_release(void) {
}

void CameraModeTitle_initialise(void) {
}

CameraModeTitlePose gCameraModeTitlePoseTable[CAMERA_MODE_TITLE_POSE_COUNT] = {
    {-18848.0f, 29.5f, 28386.0f, 21592, 1456, 0},        {-18845.0f, 21.0f, 28565.0f, 49876, 65040, 64626},
    {-18947.0f, 25.0f, 28509.0f, 13804, 1994, 0},        {-18949.0f, 54.0f, 28324.0f, 26248, 65226, 0},
    {-18876.25f, 33.25548f, 28366.39f, 9419, 3496, 170},
};

CameraModeTitleDescriptor gCameraModeTitleDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModeTitle_initialise,
    CameraModeTitle_release,
    NULL,
    CameraModeTitle_init,
    CameraModeTitle_update,
    CameraModeTitle_loadVolumes,
    CameraModeTitle_moveCam,
};
