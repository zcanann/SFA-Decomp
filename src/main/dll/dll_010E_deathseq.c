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

extern void setScreenTransitionPause(int v);
extern void addButtonObject(int* obj);
extern void removeButtonObject(int* obj);
/* .sdata2 constant pool */
static const f32 lbl_803E3D18 = 50.0f;
static const f32 lbl_803E3D1C = 0.0f;
static const f32 lbl_803E3D20 = 0.005f;
static const f32 lbl_803E3D24 = 0.5f;
static const f32 lbl_803E3D28 = 1.0f;
static const f32 lbl_803E3D2C = 40.0f;
static const f32 gDeathSeqCameraYawAngle = -0.7853982f;
static const f32 gDeathSeqCameraPitchAngle = 0.3926991f;
static const f32 lbl_803E3D38 = 10.0f;
static const f32 gDeathSeqPi = 3.1415927f;
static const f32 gDeathSeqAngleHalfCircle = 32768.0f;
static const f32 gDeathSeqCameraFovY = 60.0f;
static const f32 lbl_803E3D48 = 0.01f;
static const f64 lbl_803E3D50 = 4503601774854144.0;
static const f32 lbl_803E3D58 = 210.0f;

int DeathSeq_getExtraSize(void)
{
    return 0x24;
}
int DeathSeq_getObjectTypeId(void)
{
    return 0x0;
}

void DeathSeq_free(int* obj)
{
    setScreenTransitionPause(0);
    setPendingMapLoad(0);
    removeButtonObject(obj);
}

void DeathSeq_render(void)
{
}

void DeathSeq_hitDetect(void)
{
}

void DeathSeq_update(int* obj)
{

    CameraViewSlot* cam = Camera_GetCurrentViewSlot();
    DeathSeqState* state = ((GameObject*)obj)->extra;
    int ready;
    GameObject* player = Obj_GetPlayerObject();
    ObjTextureRuntimeSlot* tex;

    ready = 0;
    if (playerIsDead(player) != 0)
    {
        state->distTarget = lbl_803E3D18;
        if (((GameObject*)obj)->anim.currentMove != 0x92)
        {
            AudioStream_StopCurrent();
            AudioStream_Play(0x51e1, AudioStream_StartPrepared);
            ObjAnim_SetCurrentMove((int)obj, 0x92, lbl_803E3D1C, 0);
        }
        ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E3D20, timeDelta, NULL);
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E3D24)
        {
            tex = objFindTexture((GameObject*)(obj), 5, 0);
            tex->textureId = 0;
            tex = objFindTexture((GameObject*)(obj), 4, 0);
            tex->textureId = 0;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E3D28)
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
                Obj_FreeObject((GameObject*)obj);
            }
        }
        else
        {
            ready = 1;
        }
    }
    else
    {
        state->distTarget = lbl_803E3D2C;
        if ((*gScreenTransitionInterface)->isFinished() != 0)
        {
            ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E3D20, timeDelta, NULL);
            ready = 1;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E3D24)
        {
            tex = objFindTexture((GameObject*)(obj), 5, 0);
            tex->textureId = 0x200;
            tex = objFindTexture((GameObject*)(obj), 4, 0);
            tex->textureId = 0x200;
        }
        state->timer -= timeDelta;
        if (state->timer <= lbl_803E3D1C)
        {
            state->timer = lbl_803E3D1C;
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
        f32 dz = state->dist * cos34;
        f32 sin34 = state->dist * cosPitch;
        sin30 = sin34 * sin30;
        sin34 = sin34 * cos30;
        cam->yaw = 0x2000;
        cam->pitch = 0x1000;
        xTerm = lbl_803E3D38 * -mathSinf((gDeathSeqPi * (f32) * (s16*)obj) / gDeathSeqAngleHalfCircle);
        zTerm = (fz = lbl_803E3D38) * -mathCosf((gDeathSeqPi * (f32) * (s16*)obj) / gDeathSeqAngleHalfCircle);
        cam->x = sin30 + (((GameObject*)obj)->anim.worldPosX + xTerm);
        fy = fz + ((GameObject*)obj)->anim.worldPosY;
        cam->y = fy + dz;
        cam->z = sin34 + (((GameObject*)obj)->anim.worldPosZ + zTerm);
        Camera_SetFovY(gDeathSeqCameraFovY);
        state->camActive = 1;
        state->dist += interpolate(state->distTarget - state->dist, lbl_803E3D48, timeDelta);
        Rcp_SetViewFinderHudEnabled(0);
    }
    else
    {
        cam->yaw = state->camRotY;
        cam->pitch = state->camRotX;
        cam->x = state->camX;
        cam->y = state->camY;
        cam->z = state->camZ;
        state->camActive = 0;
    }

    if (state->camActive)
    {
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
    }
}

void DeathSeq_init(int* obj)
{
    DeathSeqState* state = ((GameObject*)obj)->extra;
    CameraViewSlot* cam = Camera_GetCurrentViewSlot();
    f32 dist;

    setScreenTransitionPause(1);
    (*gScreenTransitionInterface)->start(1, 1);
    ObjAnim_SetCurrentMove((int)obj, 0x8e, lbl_803E3D1C, 0);
    state->timer = lbl_803E3D58;
    state->camX = cam->x;
    state->camY = cam->y;
    state->camZ = cam->z;
    state->camRotY = cam->yaw;
    state->camRotX = cam->pitch;
    dist = lbl_803E3D2C;
    state->dist = dist;
    state->distTarget = dist;
    addButtonObject(obj);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x400);
}

void DeathSeq_release(void)
{
}

void DeathSeq_initialise(void)
{
}
