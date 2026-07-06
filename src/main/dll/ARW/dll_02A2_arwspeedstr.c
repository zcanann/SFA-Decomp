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
#include "main/game_object.h"


typedef struct ARWSpeedStrState
{
    f32 speed;
    f32 lifeTimer;
    f32 alpha;
    f32 spreadX;
    f32 spreadY;
    f32 viewZ;
    u8 flags;
    u8 pad19[3];
} ARWSpeedStrState;

STATIC_ASSERT(sizeof(ARWSpeedStrState)== 0x1c);
STATIC_ASSERT(offsetof(ARWSpeedStrState, speed)== 0x00);
STATIC_ASSERT(offsetof(ARWSpeedStrState, lifeTimer)== 0x04);
STATIC_ASSERT(offsetof(ARWSpeedStrState, alpha)== 0x08);
STATIC_ASSERT(offsetof(ARWSpeedStrState, spreadX)== 0x0c);
STATIC_ASSERT(offsetof(ARWSpeedStrState, spreadY)== 0x10);
STATIC_ASSERT(offsetof(ARWSpeedStrState, viewZ)== 0x14);
STATIC_ASSERT(offsetof(ARWSpeedStrState, flags)== 0x18);

typedef struct ARWSpeedStrVelocity
{
    f32 x;
    f32 y;
    f32 z;
} ARWSpeedStrVelocity;

STATIC_ASSERT(offsetof(ARWSpeedStrVelocity, x)== 0x00);
STATIC_ASSERT(offsetof(ARWSpeedStrVelocity, y)== 0x04);
STATIC_ASSERT(offsetof(ARWSpeedStrVelocity, z)== 0x08);

int arwspeedstr_getExtraSize(void) { return 0x1c; }

int arwspeedstr_getObjectTypeId(void) { return 0; }

void arwspeedstr_free(void)
{
}

void arwspeedstr_hitDetect(void)
{
}

void arwspeedstr_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7100);
}

void arwspeedstr_init(int obj, int setup)
{
    ((GameObject*)obj)->anim.alpha = 0;
}

void arwspeedstr_release(void)
{
}

void arwspeedstr_initialise(void)
{
}

void arwspeedstr_update(int obj)
{
    ARWSpeedStrState* state = ((GameObject*)obj)->extra;
    if (state->flags == 0)
    {
        f32 camOffset[3];
        camOffset[0] = (f32)(int)
        randomGetRange((int)-state->spreadX, state->spreadX);
        camOffset[1] =
            (f32)(int)
        randomGetRange((int)-state->spreadY, state->spreadY);
        camOffset[2] = state->viewZ;
        PSMTXMultVec(Camera_GetInverseViewMatrix(), &camOffset[0], (f32*)((char*)obj + 12));
        ((GameObject*)obj)->anim.localPosX += playerMapOffsetX;
        ((GameObject*)obj)->anim.localPosZ += playerMapOffsetZ;
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
        objMove(obj, zero, zero, state->speed * timeDelta);
        state->alpha = lbl_803E7108 * timeDelta + state->alpha;
        if (state->alpha > *(f32*)&lbl_803E710C)
            state->alpha = lbl_803E710C;
        ((GameObject*)obj)->anim.alpha = state->alpha;
    }
}

void fn_80231058(int obj, int src)
{
    ((GameObject*)obj)->anim.velocityX = ((ARWSpeedStrVelocity*)src)->x;
    ((GameObject*)obj)->anim.velocityY = ((ARWSpeedStrVelocity*)src)->y;
    ((GameObject*)obj)->anim.velocityZ = ((ARWSpeedStrVelocity*)src)->z;
}

void fn_80231028(int obj, int speed)
{
    ARWSpeedStrState* state = ((GameObject*)obj)->extra;
    state->speed = speed;
}
