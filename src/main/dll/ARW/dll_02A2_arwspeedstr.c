/*
 * arwspeedstr (DLL 0x2A2) - the streaking "speed line" particles that fly
 * past the camera during the on-rails Arwing sections, conveying forward
 * speed. On first update each streak picks a random spread offset in
 * camera space, transforms it through the inverse view matrix into world
 * space and biases it by the player's map offset. It then drifts along its
 * own velocity, fading its alpha up to a cap over its life timer before
 * freeing itself when the timer runs out.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/ARW/dll_02A2_arwspeedstr.h"
#include "main/game_object.h"

int ARWSpeedStr_getExtraSize(void)
{
    return 0x1c;
}

int ARWSpeedStr_getObjectTypeId(void)
{
    return 0;
}

void ARWSpeedStr_free(void)
{
}

void ARWSpeedStr_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7100);
}

void ARWSpeedStr_hitDetect(void)
{
}

void ARWSpeedStr_update(GameObject* obj)
{
    ARWSpeedStrState* state = (obj)->extra;
    if (state->flags == 0)
    {
        f32 camOffset[3];
        camOffset[0] = (f32)(int)randomGetRange((int)-state->spreadX, state->spreadX);
        camOffset[1] = (f32)(int)randomGetRange((int)-state->spreadY, state->spreadY);
        camOffset[2] = state->viewZ;
        PSMTXMultVec(Camera_GetInverseViewMatrix(), &camOffset[0], (f32*)((char*)obj + 12));
        (obj)->anim.localPosX += playerMapOffsetX;
        (obj)->anim.localPosZ += playerMapOffsetZ;
        state->flags = (state->flags | 1) & 0xff;
        state->alpha = lbl_803E7104;
    }
    {
        f32 lifeTimer = state->lifeTimer;
        f32 zero = lbl_803E7104;
        if (lifeTimer > zero)
        {
            state->lifeTimer = lifeTimer - timeDelta;
            if (state->lifeTimer <= zero)
            {
                state->lifeTimer = zero;
                Obj_FreeObject(obj);
                return;
            }
        }
        else
        {
            return;
        }
        objMove((int)obj, zero, zero, state->speed * timeDelta);
        state->alpha = lbl_803E7108 * timeDelta + state->alpha;
        if (state->alpha > *(f32*)&lbl_803E710C)
            state->alpha = lbl_803E710C;
        (obj)->anim.alpha = state->alpha;
    }
}

void ARWSpeedStr_init(GameObject* obj, int setup)
{
    obj->anim.alpha = 0;
}

void ARWSpeedStr_release(void)
{
}

void ARWSpeedStr_initialise(void)
{
}

void fn_80231028(GameObject* obj, int speed)
{
    ARWSpeedStrState* state = obj->extra;
    state->speed = speed;
}

void fn_80231058(GameObject* obj, int src)
{
    obj->anim.velocityX = ((ARWSpeedStrVelocity*)src)->x;
    obj->anim.velocityY = ((ARWSpeedStrVelocity*)src)->y;
    obj->anim.velocityZ = ((ARWSpeedStrVelocity*)src)->z;
}
