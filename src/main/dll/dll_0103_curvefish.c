#include "main/dll/dusterstate_types.h"
#include "main/game_object.h"
#include "main/dll/cfprisonuncle.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"

typedef struct CurvefishState
{
    u8 pad0[0xA - 0x0];
    s16 unkA;
    u8 padC[0x10 - 0xC];
    s16 unk10;
    u8 pad12[0x108 - 0x12];
    u8 unk108;
    u8 pad109[0x110 - 0x109];
    f32 unk110;
    u8 pad114[0x120 - 0x114];
} CurvefishState;

extern u32 randomGetRange(int min, int max);
extern void* Obj_GetPlayerObject(void);
extern int ObjHits_GetPriorityHit();
extern f32 getXZDistance(f32 * a, f32 * b);
extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern int fn_80296448(int obj);

extern u32 lbl_803E38E8;
extern f32 lbl_803E38EC;
extern f32 lbl_803E38F0;
extern f32 lbl_803E38F4;
extern f32 lbl_803E38F8;
extern f32 lbl_803E38FC;
extern f32 lbl_803E3900;
extern f32 lbl_803E3904;
extern f32 lbl_803E3908;
extern f32 lbl_803E390C;
extern f32 lbl_803E3910;
extern f32 lbl_803E3914;
extern f32 timeDelta;


STATIC_ASSERT(sizeof(DusterStateFlags) == 1);
STATIC_ASSERT(sizeof(DusterState) == 0x20);
STATIC_ASSERT(offsetof(DusterState, moveStepScale) == 0x00);
STATIC_ASSERT(offsetof(DusterState, floorY) == 0x04);
STATIC_ASSERT(offsetof(DusterState, settleTimer) == 0x08);
STATIC_ASSERT(offsetof(DusterState, hitReactTimer) == 0x0a);
STATIC_ASSERT(offsetof(DusterState, completeGameBit) == 0x0c);
STATIC_ASSERT(offsetof(DusterState, activeGameBit) == 0x0e);
STATIC_ASSERT(offsetof(DusterState, heldObjectId) == 0x10);
STATIC_ASSERT(offsetof(DusterState, driftDir) == 0x18);
STATIC_ASSERT(offsetof(DusterState, hitReactActive) == 0x19);
STATIC_ASSERT(offsetof(DusterState, priorityHit) == 0x1a);
STATIC_ASSERT(offsetof(DusterState, active) == 0x1b);
STATIC_ASSERT(offsetof(DusterState, complete) == 0x1c);
STATIC_ASSERT(offsetof(DusterState, useLaunchVelocity) == 0x1d);
STATIC_ASSERT(offsetof(DusterState, flags) == 0x1e);
extern const f32 lbl_803E3928;

int curvefish_getExtraSize(void) { return 0x120; }













typedef struct CurveFishSetup
{
    u8 pad00[8];
    f32 spawnX;
    f32 spawnY;
    f32 spawnZ;
    u8 pad14[5];
    u8 speedChange;
    u8 pad1A[6];
    u16 waitFrames;
    u8 targetYOffset;
    u8 playerRadius;
} CurveFishSetup;

typedef struct CurveFishState
{
    u8 pad00[0x10];
    int hasRouteEdge;
    u8 pad14[0x54];
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    u8 pad74[0x30];
    int routeCursor;
    u8 padA8[0x60];
    u8 mode;
    u8 pad109[3];
    f32 animTimer;
    f32 maxSpeed;
    f32 speed;
    f32 moveStepScale;
    f32 phaseTimer;
} CurveFishState;


void curvefish_update(int obj)
{
    CurveFishState* state;
    CurveFishSetup* setup;
    void* player;
    CurveFishSetup* setup2;
    u32 curveQuery;
    int firstNode;
    int secondNode;
    int thirdNode;
    int nextNode;
    f32 maxHitSpeed;
    f32 speedThreshold;
    f32 distLimit;
    f32 distance;
    int i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 mag;
    s16 targetYaw;
    int yawDelta;

    state = ((GameObject*)obj)->extra;
    setup = *(CurveFishSetup**)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    setup2 = *(CurveFishSetup**)&((GameObject*)obj)->anim.placementData;
    curveQuery = lbl_803E38E8;

    state->phaseTimer += timeDelta;

    switch (state->mode)
    {
    case 0:
        {
            f32 waitTime = lbl_803E38EC * (f32)(u32)
            setup->waitFrames;
            if (!(state->phaseTimer >= waitTime))
            {
                return;
            }
            state->phaseTimer -= waitTime;
            state->mode = 1;
        }
    case 1:
        ((GameObject*)obj)->anim.localPosX = setup2->spawnX;
        ((GameObject*)obj)->anim.localPosY = setup2->spawnY;
        ((GameObject*)obj)->anim.localPosZ = setup2->spawnZ;

        firstNode = (int)(*gRomCurveInterface)->getById(
            (*gRomCurveInterface)->find((int*)&curveQuery, 1, -1, ((GameObject*)obj)->anim.localPosX,
                                        ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ));
        secondNode = (int)(*gRomCurveInterface)->getById(
            ((int (*)(int, int))(*gRomCurveInterface)->slot54)(firstNode, 0));
        thirdNode = (int)(*gRomCurveInterface)->getById(
            ((int (*)(int, int))(*gRomCurveInterface)->slot54)(secondNode, 0));

        if (fn_800DA980((RomCurveWalker*)state, (void*)firstNode, (void*)secondNode, (void*)thirdNode) != 0)
        {
            return;
        }
        state->mode = 2;
        state->speed = lbl_803E38F0;
    case 2:
        if (state->phaseTimer <= lbl_803E38EC)
        {
            ((GameObject*)obj)->anim.alpha =
                (u8)(int)(lbl_803E38F4 * (state->phaseTimer / lbl_803E38EC));
            return;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        state->mode = 3;
        break;
    case 3:
        break;
    default:
        return;
    }

    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
    {
        state->speed = lbl_803E38F8 * state->maxSpeed;
    }
    else if (fn_80296448((int)player) != 0 &&
        getXZDistance(&((GameObject*)player)->anim.localPosX, (f32*)(obj + 0xc)) <
        (f32)(u32)
            setup->playerRadius * (f32)(u32)
    setup->playerRadius
    )
    {
        state->speed +=
            ((lbl_803E38F8 * (f32)(u32)
        setup2->speedChange
        )
        *timeDelta
        )
        /
        lbl_803E38FC;
        maxHitSpeed = lbl_803E38F8 * state->maxSpeed;
        if (state->speed > maxHitSpeed)
        {
            state->speed = maxHitSpeed;
        }
    }
    else
    {
        state->speed += ((f32)(int)
        randomGetRange(-(int)setup2->speedChange,
                       (int)setup2->speedChange << 1) *
            timeDelta
        )
        /
        lbl_803E38FC;
        if (state->speed < lbl_803E38F0)
        {
            state->speed = lbl_803E38F0;
        }
        else if (state->speed > state->maxSpeed)
        {
            state->speed = state->maxSpeed;
        }
    }

    speedThreshold = state->maxSpeed * lbl_803E3900;
    if (state->speed < speedThreshold)
    {
        if (((GameObject*)obj)->anim.currentMove == 0 && state->animTimer > lbl_803E3904)
        {
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E38F0, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
            state->animTimer = lbl_803E38F0;
        }
        state->moveStepScale = lbl_803E3908;
    }
    else if (state->speed > lbl_803E390C * state->maxSpeed * lbl_803E3900)
    {
        if (((GameObject*)obj)->anim.currentMove == 0 && state->animTimer > lbl_803E3910)
        {
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E38F0, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
            state->animTimer = lbl_803E38F0;
        }
        state->moveStepScale = lbl_803E3914;
    }
    else
    {
        if (((GameObject*)obj)->anim.currentMove == 1 && state->animTimer > lbl_803E3910)
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E38F0, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
            state->animTimer = lbl_803E38F0;
        }
        state->moveStepScale = (lbl_803E3914 * state->speed) / state->maxSpeed;
    }

    if (state->speed != lbl_803E38F0)
    {
        distLimit = state->speed * timeDelta;
        distLimit *= distLimit;
        distance = getXZDistance(&state->targetX, (f32*)(obj + 0xc));
        i = 0;
        while (distance < distLimit && i < 5)
        {
            Curve_AdvanceAlongPath((RomCurveWalker*)state, lbl_803E38F8);
            distance = getXZDistance(&state->targetX, (f32*)(obj + 0xc));
            i++;
        }

        if (state->hasRouteEdge != 0)
        {
            nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot54)(state->routeCursor, 0);
            if (curveFn_800da23c((RomCurveWalker*)state, (*gRomCurveInterface)->getById(nextNode)) != 0)
            {
                state->mode = 0;
                state->phaseTimer = lbl_803E38F0;
                ((GameObject*)obj)->anim.alpha = 0;
                return;
            }
        }

        dx = state->targetX - ((GameObject*)obj)->anim.localPosX;
        dy = (state->targetY + (f32)(u32)
        setup->targetYOffset
        )
        -((GameObject*)obj)->anim.localPosY;
        dz = state->targetZ - ((GameObject*)obj)->anim.localPosZ;
        mag = sqrtf(dx * dx + dy * dy + dz * dz);
        dx /= mag;
        dy /= mag;
        dz /= mag;

        ((GameObject*)obj)->anim.localPosX += dx * state->speed;
        ((GameObject*)obj)->anim.localPosY += dy * state->speed;
        ((GameObject*)obj)->anim.localPosZ += dz * state->speed;

        targetYaw = getAngle(dx, dz);
        yawDelta = (s16)targetYaw - ((u16) * (s16*)obj);
        if (yawDelta > 0x8000)
        {
            yawDelta -= 0xffff;
        }
        if (yawDelta < -0x8000)
        {
            yawDelta += 0xffff;
        }
        if (yawDelta > 0x180)
        {
            ((GameObject*)obj)->anim.rotX += 0x180;
        }
        else if (yawDelta < -0x180)
        {
            ((GameObject*)obj)->anim.rotX -= 0x180;
        }
        else
        {
            ((GameObject*)obj)->anim.rotX = targetYaw;
        }
    }

    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->moveStepScale, timeDelta, NULL);
    state->animTimer += timeDelta;
}

void curvefish_init(int obj, u8* param_2)
{
    int state;
    u32 v;
    state = *(int*)&((GameObject*)obj)->extra;
    v = ((GameObject*)obj)->objectFlags;
    v |= 0x6000;
    ((GameObject*)obj)->objectFlags = (u16)v;
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase *
        ((f32)(u32)
    param_2[0x18] / lbl_803E3928
    )
    ;
    ((CurvefishState*)state)->unk108 = 1;
    ((CurvefishState*)state)->unk110 = (f32)(u32)
    param_2[0x19] / lbl_803E3928;
}

void trickyguard_update(int* obj);


ObjectDescriptor gMagicPlantObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicPlant_init,
    (ObjectDescriptorCallback)MagicPlant_update,
    0,
    (ObjectDescriptorCallback)MagicPlant_render,
    (ObjectDescriptorCallback)MagicPlant_free,
    (ObjectDescriptorCallback)MagicPlant_getObjectTypeId,
    MagicPlant_getExtraSize,
};

ObjectDescriptor gTrickyWarpObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_init,
    (ObjectDescriptorCallback)trickywarp_update,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_free,
    0,
    trickywarp_getExtraSize,
};

ObjectDescriptor gTrickyGuardObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickyguard_init,
    (ObjectDescriptorCallback)trickyguard_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gStayPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)StayPoint_init,
    (ObjectDescriptorCallback)StayPoint_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gDusterObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)duster_init,
    (ObjectDescriptorCallback)duster_update,
    (ObjectDescriptorCallback)duster_hitDetect,
    (ObjectDescriptorCallback)duster_render,
    0,
    0,
    duster_getExtraSize,
};

ObjectDescriptor gCurveFishObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curvefish_init,
    (ObjectDescriptorCallback)curvefish_update,
    0,
    0,
    0,
    0,
    curvefish_getExtraSize,
};
