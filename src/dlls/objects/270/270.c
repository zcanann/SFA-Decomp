/*
 * DeathSeq object (DLL slot 270).
 *
 * Owns the death-menu model, fade sequence, and temporary camera override.
 */
#include "dlls/objects/270.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/stream_api.h"
#include "main/camera.h"
#include "main/dll/player_status.h"
#include "main/frame_timing.h"
#include "main/gameloop_api.h"
#include "main/objtexture.h"
#include "main/screen_transition.h"
#include "sys/objects.h"
#include "main/dll/tricky_api.h"
#include "main/lightmap_api.h"
#include "main/rcp_dolphin.h"
#include "sys/objects/lifecycle.h"
#include "main/vecmath.h"

static const f32 gDeathSeqCameraYawAngle = -0.7853982f;
static const f32 gDeathSeqCameraPitchAngle = 0.3926991f;
static const f32 gDeathSeqPi = 3.1415927f;
static const f32 gDeathSeqAngleHalfCircle = 32768.0f;
static const f32 gDeathSeqCameraFovY = 60.0f;

#define DEATH_SEQ_MOVE_IDLE              0x8E
#define DEATH_SEQ_MOVE_DEATH             0x92
#define DEATH_SEQ_AUDIO_STREAM_ID        0x51E1
#define DEATH_SEQ_ANIMATION_STEP         0.005f
#define DEATH_SEQ_TEXTURE_SWAP_PROGRESS  0.5f
#define DEATH_SEQ_ANIMATION_END_PROGRESS 1.0f
#define DEATH_SEQ_TEXTURE_SLOT_A         5
#define DEATH_SEQ_TEXTURE_SLOT_B         4
#define DEATH_SEQ_TEXTURE_ID_HIDDEN      0
#define DEATH_SEQ_TEXTURE_ID_VISIBLE     0x200
#define DEATH_SEQ_DEAD_CAMERA_DISTANCE   50.0f
#define DEATH_SEQ_ALIVE_CAMERA_DISTANCE  40.0f
#define DEATH_SEQ_OBJECT_CAMERA_OFFSET   10.0f
#define DEATH_SEQ_DISTANCE_INTERPOLATION 0.01f
#define DEATH_SEQ_MENU_DELAY             210.0f
#define DEATH_SEQ_FADE_OUT_FRAMES        1
#define DEATH_SEQ_FADE_IN_FRAMES         10
#define DEATH_SEQ_CAMERA_YAW             0x2000
#define DEATH_SEQ_CAMERA_PITCH           0x1000

int DeathSeq_getExtraSize(void) {
    return sizeof(DeathSeqState);
}

int DeathSeq_getObjectTypeId(void) {
    return 0;
}

void DeathSeq_free(GameObject* obj) {
    setScreenTransitionPause(FALSE);
    setPendingMapLoad(FALSE);
    removeButtonObject(obj);
}

void DeathSeq_render(void) {
}

void DeathSeq_hitDetect(void) {
}

void DeathSeq_update(GameObject* obj) {
    Camera* camera = Camera_GetCurrent();
    DeathSeqState* state = obj->extra;
    int useDeathCamera;
    GameObject* player = Obj_GetPlayerObject();
    ObjTextureRuntimeSlot* texture;

    useDeathCamera = FALSE;
    /* Revival and death are separate player flags. playerHeal raises the
     * revival flag; playerDie clears it and raises the death flag. */
    if (playerHasRevived(player) != 0) {
        state->cameraDistanceTarget = DEATH_SEQ_DEAD_CAMERA_DISTANCE;
        if (obj->anim.currentMove != DEATH_SEQ_MOVE_DEATH) {
            AudioStream_StopCurrent();
            AudioStream_Play(DEATH_SEQ_AUDIO_STREAM_ID, AudioStream_StartPrepared);
            ObjAnim_SetCurrentMove(obj, DEATH_SEQ_MOVE_DEATH, 0.0f, 0);
        }
        ObjAnim_AdvanceCurrentMove(obj, DEATH_SEQ_ANIMATION_STEP, timeDelta, NULL);
        if (obj->anim.currentMoveProgress > DEATH_SEQ_TEXTURE_SWAP_PROGRESS) {
            texture = objFindTexture(obj, DEATH_SEQ_TEXTURE_SLOT_A, 0);
            texture->textureId = DEATH_SEQ_TEXTURE_ID_HIDDEN;
            texture = objFindTexture(obj, DEATH_SEQ_TEXTURE_SLOT_B, 0);
            texture->textureId = DEATH_SEQ_TEXTURE_ID_HIDDEN;
        }
        if (obj->anim.currentMoveProgress >= DEATH_SEQ_ANIMATION_END_PROGRESS) {
            if (!state->flags.transitionStarted) {
                setScreenTransitionPause(FALSE);
                (*gScreenTransitionInterface)->step(DEATH_SEQ_FADE_IN_FRAMES, SCREEN_TRANSITION_BLACK);
                state->flags.transitionStarted = TRUE;
            }
            if ((*gScreenTransitionInterface)->isFinished() != 0) {
                if (player != NULL) {
                    playerSetIsDead(player, FALSE);
                }
                cutsceneFadeInOut(FALSE);
                setPendingMapLoad(FALSE);
                Obj_FreeObject(obj);
            }
        } else {
            useDeathCamera = TRUE;
        }
    } else {
        state->cameraDistanceTarget = DEATH_SEQ_ALIVE_CAMERA_DISTANCE;
        if ((*gScreenTransitionInterface)->isFinished() != 0) {
            ObjAnim_AdvanceCurrentMove(obj, DEATH_SEQ_ANIMATION_STEP, timeDelta, NULL);
            useDeathCamera = TRUE;
        }
        if (obj->anim.currentMoveProgress > DEATH_SEQ_TEXTURE_SWAP_PROGRESS) {
            texture = objFindTexture(obj, DEATH_SEQ_TEXTURE_SLOT_A, 0);
            texture->textureId = DEATH_SEQ_TEXTURE_ID_VISIBLE;
            texture = objFindTexture(obj, DEATH_SEQ_TEXTURE_SLOT_B, 0);
            texture->textureId = DEATH_SEQ_TEXTURE_ID_VISIBLE;
        }
        state->menuDelay -= timeDelta;
        if (state->menuDelay <= 0.0f) {
            state->menuDelay = 0.0f;
            if (!state->flags.menuShown) {
                showDeathMenu();
                state->flags.menuShown = TRUE;
            }
        }
    }

    if (useDeathCamera != 0) {
        f32 sinYaw = mathSinf(gDeathSeqCameraYawAngle);
        f32 cosYaw = mathCosf(gDeathSeqCameraYawAngle);
        f32 cosPitch = mathCosf(gDeathSeqCameraPitchAngle);
        f32 sinPitch = mathSinf(gDeathSeqCameraPitchAngle);
        f32 objectOffsetX;
        f32 cameraY;
        f32 objectHeightOffset;
        f32 objectOffsetZ;
        f32 cameraVerticalOffset = state->cameraDistance * sinPitch;
        f32 cameraHorizontalOffset = state->cameraDistance * cosPitch;
        cosYaw = cameraHorizontalOffset * cosYaw;
        cameraHorizontalOffset *= sinYaw;
        camera->yaw = DEATH_SEQ_CAMERA_YAW;
        camera->pitch = DEATH_SEQ_CAMERA_PITCH;
        objectOffsetX =
            DEATH_SEQ_OBJECT_CAMERA_OFFSET * -mathSinf((gDeathSeqPi * (f32)obj->anim.rotX) / gDeathSeqAngleHalfCircle);
        objectOffsetZ = (objectHeightOffset = DEATH_SEQ_OBJECT_CAMERA_OFFSET) *
                        -mathCosf((gDeathSeqPi * (f32)obj->anim.rotX) / gDeathSeqAngleHalfCircle);
        camera->x = cosYaw + (obj->anim.worldPosX + objectOffsetX);
        cameraY = objectHeightOffset + obj->anim.worldPosY;
        camera->y = cameraY + cameraVerticalOffset;
        camera->z = cameraHorizontalOffset + (obj->anim.worldPosZ + objectOffsetZ);
        Camera_SetFovY(gDeathSeqCameraFovY);
        state->flags.cameraActive = TRUE;
        state->cameraDistance += interpolate(state->cameraDistanceTarget - state->cameraDistance,
                                             DEATH_SEQ_DISTANCE_INTERPOLATION, timeDelta);
        Rcp_SetViewFinderHudEnabled(FALSE);
    } else {
        camera->yaw = state->savedCameraYaw;
        camera->pitch = state->savedCameraPitch;
        camera->x = state->savedCameraX;
        camera->y = state->savedCameraY;
        camera->z = state->savedCameraZ;
        state->flags.cameraActive = FALSE;
    }

    if (state->flags.cameraActive) {
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    } else {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
}

void DeathSeq_init(GameObject* obj) {
    DeathSeqState* state = obj->extra;
    Camera* camera = Camera_GetCurrent();
    f32 distance;

    setScreenTransitionPause(TRUE);
    (*gScreenTransitionInterface)->start(DEATH_SEQ_FADE_OUT_FRAMES, SCREEN_TRANSITION_BLACK);
    ObjAnim_SetCurrentMove(obj, DEATH_SEQ_MOVE_IDLE, 0.0f, 0);
    state->menuDelay = DEATH_SEQ_MENU_DELAY;
    state->savedCameraX = camera->x;
    state->savedCameraY = camera->y;
    state->savedCameraZ = camera->z;
    state->savedCameraYaw = camera->yaw;
    state->savedCameraPitch = camera->pitch;
    distance = DEATH_SEQ_ALIVE_CAMERA_DISTANCE;
    state->cameraDistance = distance;
    state->cameraDistanceTarget = distance;
    addButtonObject(obj);
    obj->objectFlags |= OBJECT_OBJFLAG_SHADOW_DISABLED;
}

void DeathSeq_release(void) {
}

void DeathSeq_initialise(void) {
}

ObjectDescriptor gDeathSeqObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DeathSeq_initialise,
    (ObjectDescriptorCallback)DeathSeq_release,
    0,
    (ObjectDescriptorCallback)DeathSeq_init,
    (ObjectDescriptorCallback)DeathSeq_update,
    (ObjectDescriptorCallback)DeathSeq_hitDetect,
    (ObjectDescriptorCallback)DeathSeq_render,
    (ObjectDescriptorCallback)DeathSeq_free,
    (ObjectDescriptorCallback)DeathSeq_getObjectTypeId,
    DeathSeq_getExtraSize,
};
