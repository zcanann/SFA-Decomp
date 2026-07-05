/* DLL 0x004F - Camera mode misc handler [0x8010F2F8-0x8010F540). */
#include "main/mm.h"
extern float mathSinf(float x);
extern float mathCosf(float x);
#include "main/camera_object.h"
#include "main/dll/CAM/camera_mode_4f_state.h"
#include "main/dll/CAM/camcloudrunner_state.h"
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"

#pragma scheduling on
#pragma peephole on
extern CameraMode4FState* gCameraMode4FState;
extern f32 Curve_EvalHermite(f32* pts, f32 t, int mode);


#pragma scheduling off
#pragma peephole off
void dll_4F_func06_nop(void)
{
}

void dll_4F_func05(void)
{
    extern void mm_free(u32); /* #57 */
    mm_free((u32)gCameraMode4FState);
    gCameraMode4FState = NULL;
}


void dll_4F_update(int* obj)
{
    CameraObject* camera;
    GameObject* target;
    f32 pts[4];
    f32 fz;
    f32 sn;
    f32 cs;
    s16 a;

    camera = (CameraObject*)obj;
    pts[0] = 0.0f;
    pts[1] = 1.0f;
    pts[2] = 0.0f;
    pts[3] = 0.0f;
    fz = Curve_EvalHermite(pts, gCameraMode4FState->blendProgress, 0);
    a = (s16)(0x8000 - ((GameObject*)camera->anim.targetObj)->anim.rotX);
    a += (s32)(14560.0f * fz);
    target = (GameObject*)camera->anim.targetObj;
    {
        f32 t = (3.1415927f * (f32)(s32)
        a
        )
        /
        32768.0f;
        sn = mathCosf(t);
        cs = mathSinf(t);
    }
    camera->anim.localPosX = target->anim.worldPosX + (20.0f * sn - -10.0f * cs);
    camera->anim.localPosZ = target->anim.worldPosZ + (20.0f * cs + -10.0f * sn);
    camera->anim.localPosY = (35.0f + target->anim.worldPosY) - 15.0f * fz;
    camera->anim.rotY = (s16)(0x11c6 - (s32)(35.0f * (182.0f * fz)));
    camera->anim.rotX = (s16)(a + 0x1ffe);
    camera->anim.rotZ = 0;
    camera->letterboxTargetOffset = 0;
    camera->fov = 60.0f;
    gCameraMode4FState->blendProgress += 0.005f * timeDelta;
    if (gCameraMode4FState->blendProgress > 1.0f)
    {
        gCameraMode4FState->blendProgress = 1.0f;
    }
}


void dll_4F_init(void)
{
    if (gCameraMode4FState == NULL)
    {
        gCameraMode4FState = (CameraMode4FState*)mmAlloc(sizeof(CameraMode4FState), 15, 0);
    }
    gCameraMode4FState->blendProgress = 0.0f;
}

void dll_4F_release_nop(void)
{
}

void dll_4F_initialise_nop(void)
{
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
