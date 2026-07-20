/* DLL 0x10E - DeathSeq [8018BC48-8018BC50) */
#include "main/objseq.h"
#include "main/object_api.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/objtexture.h"
#include "main/screen_transition.h"
#include "main/camera.h"
#include "main/rcp_dolphin.h"
#include "main/audio/stream_api.h"
#include "main/camera.h"
#include "main/gameloop_api.h"
#include "main/lightmap_api.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/dll/dll_010E_deathseq.h"
#include "main/dll/player_status.h"
#include "main/dll/tricky_api.h"
#include "main/object_descriptor.h"

static const f32 gDeathSeqCameraYawAngle = -0.7853982f;
static const f32 gDeathSeqCameraPitchAngle = 0.3926991f;
static const f32 gDeathSeqPi = 3.1415927f;
static const f32 gDeathSeqAngleHalfCircle = 32768.0f;
static const f32 gDeathSeqCameraFovY = 60.0f;

int DeathSeq_getExtraSize(void)
{
    return 0x24;
}
int DeathSeq_getObjectTypeId(void)
{
    return 0x0;
}

void DeathSeq_free(GameObject* obj)
{
    setScreenTransitionPause(0);
    setPendingMapLoad(0);
    removeButtonObject((u32)obj);
}

void DeathSeq_render(void)
{
}

void DeathSeq_hitDetect(void)
{
}

void DeathSeq_update(GameObject* obj)
{

    CameraViewSlot* cam = Camera_GetCurrentViewSlot();
    DeathSeqState* state = obj->extra;
    int ready;
    GameObject* player = Obj_GetPlayerObject();
    ObjTextureRuntimeSlot* tex;

    ready = 0;
    if (playerIsDead(player) != 0)
    {
        state->cameraDistanceTarget = 50.0f;
        if (obj->anim.currentMove != 0x92)
        {
            AudioStream_StopCurrent();
            AudioStream_Play(0x51e1, AudioStream_StartPrepared);
            ObjAnim_SetCurrentMove((int)obj, 0x92, 0.0f, 0);
        }
        ObjAnim_AdvanceCurrentMove((int)obj, 0.005f, timeDelta, NULL);
        if (obj->anim.currentMoveProgress > 0.5f)
        {
            tex = objFindTexture(obj, 5, 0);
            tex->textureId = 0;
            tex = objFindTexture(obj, 4, 0);
            tex->textureId = 0;
        }
        if (obj->anim.currentMoveProgress >= 1.0f)
        {
            if (!state->transitionStarted)
            {
                setScreenTransitionPause(0);
                (*gScreenTransitionInterface)->step(10, 1);
                state->transitionStarted = 1;
            }
            if ((*gScreenTransitionInterface)->isFinished() != 0)
            {
                if (player != NULL)
                {
                    playerSetIsDead((GameObject*)(player), 0);
                }
                cutsceneFadeInOut(0);
                setPendingMapLoad(0);
                Obj_FreeObject(obj);
            }
        }
        else
        {
            ready = 1;
        }
    }
    else
    {
        state->cameraDistanceTarget = 40.0f;
        if ((*gScreenTransitionInterface)->isFinished() != 0)
        {
            ObjAnim_AdvanceCurrentMove((int)obj, 0.005f, timeDelta, NULL);
            ready = 1;
        }
        if (obj->anim.currentMoveProgress > 0.5f)
        {
            tex = objFindTexture(obj, 5, 0);
            tex->textureId = 0x200;
            tex = objFindTexture(obj, 4, 0);
            tex->textureId = 0x200;
        }
        state->timer -= timeDelta;
        if (state->timer <= 0.0f)
        {
            state->timer = 0.0f;
            if (!state->menuShown)
            {
                showDeathMenu();
                state->menuShown = 1;
            }
        }
    }

    if (ready != 0)
    {
        f32 cos30 = mathSinf(gDeathSeqCameraYawAngle);
        f32 sin30 = mathCosf(gDeathSeqCameraYawAngle);
        f32 cosPitch = mathCosf(gDeathSeqCameraPitchAngle);
        f32 cos34 = mathSinf(gDeathSeqCameraPitchAngle);
        f32 xTerm;
        f32 fy;
        f32 fz;
        f32 zTerm;
        f32 dz = state->cameraDistance * cos34;
        f32 sin34 = state->cameraDistance * cosPitch;
        sin30 = sin34 * sin30;
        sin34 = sin34 * cos30;
        cam->yaw = 0x2000;
        cam->pitch = 0x1000;
        xTerm = 10.0f * -mathSinf((gDeathSeqPi * (f32)obj->anim.rotX) / gDeathSeqAngleHalfCircle);
        zTerm = (fz = 10.0f) * -mathCosf((gDeathSeqPi * (f32)obj->anim.rotX) / gDeathSeqAngleHalfCircle);
        cam->x = sin30 + (obj->anim.worldPosX + xTerm);
        fy = fz + obj->anim.worldPosY;
        cam->y = fy + dz;
        cam->z = sin34 + (obj->anim.worldPosZ + zTerm);
        Camera_SetFovY(gDeathSeqCameraFovY);
        state->camActive = 1;
        state->cameraDistance +=
            interpolate(state->cameraDistanceTarget - state->cameraDistance, 0.01f, timeDelta);
        Rcp_SetViewFinderHudEnabled(0);
    }
    else
    {
        cam->yaw = state->savedYaw;
        cam->pitch = state->savedPitch;
        cam->x = state->savedCamX;
        cam->y = state->savedCamY;
        cam->z = state->savedCamZ;
        state->camActive = 0;
    }

    if (state->camActive)
    {
        obj->anim.flags = obj->anim.flags & ~OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
    }
}

void DeathSeq_init(GameObject* obj)
{
    DeathSeqState* state = obj->extra;
    CameraViewSlot* cam = Camera_GetCurrentViewSlot();
    f32 dist;

    setScreenTransitionPause(1);
    (*gScreenTransitionInterface)->start(1, 1);
    ObjAnim_SetCurrentMove((int)obj, 0x8e, 0.0f, 0);
    state->timer = 210.0f;
    state->savedCamX = cam->x;
    state->savedCamY = cam->y;
    state->savedCamZ = cam->z;
    state->savedYaw = cam->yaw;
    state->savedPitch = cam->pitch;
    dist = 40.0f;
    state->cameraDistance = dist;
    state->cameraDistanceTarget = dist;
    addButtonObject((int*)obj);
    obj->objectFlags = (u16)(obj->objectFlags | 0x400);
}

void DeathSeq_release(void)
{
}

void DeathSeq_initialise(void)
{
}

ObjectDescriptor gDeathSeqObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DeathSeq_initialise, (ObjectDescriptorCallback)DeathSeq_release, 0,
    (ObjectDescriptorCallback)DeathSeq_init, (ObjectDescriptorCallback)DeathSeq_update,
    (ObjectDescriptorCallback)DeathSeq_hitDetect, (ObjectDescriptorCallback)DeathSeq_render,
    (ObjectDescriptorCallback)DeathSeq_free, (ObjectDescriptorCallback)DeathSeq_getObjectTypeId,
    DeathSeq_getExtraSize,
};
