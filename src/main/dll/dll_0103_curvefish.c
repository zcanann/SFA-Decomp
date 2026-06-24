/*
 * curvefish (DLL 0x0103) - a fish that swims an endless loop along a ROM
 * curve path (Curve_AdvanceAlongPath), fading in on spawn and steering its
 * yaw toward the next path node each frame.
 *
 * curvefish_update is a four-stage state machine (CurveFishState.mode):
 *   0  wait setup->waitFrames game-frames, then advance;
 *   1  teleport to setup->spawn{X,Y,Z}, bind the walker to the three curve
 *      nodes nearest that point, seed speed; bail back to wait if the curve
 *      bind fails;
 *   2  fade alpha in over one frame-time, then go to stage 3;
 *   3  cruise: speed is bumped up on a priority hit, accelerated toward the
 *      player when in range (setup->playerRadius), else random-walked; the
 *      swim/glide animation move is chosen from the speed band and the body
 *      is stepped along the path with yaw turning capped at 0x180/frame.
 *      Reaching the route end (curveFn_800da23c) resets to stage 0.
 *
 * This TU is the shared DLL bundle for objects 0x00FE..0x0103: it also
 * defines the ObjectDescriptors for magicplant, trickywarp, trickyguard,
 * staypoint, duster and curvefish, whose callbacks live in their own TUs
 * (declared in cfprisonuncle.h).
 */
#include "main/game_object.h"
#include "main/dll/cfprisonuncle.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gameplay_runtime.h"
#include "main/objhits.h"
extern f32 getXZDistance(f32* a, f32* b);
extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern int fn_80296448(int obj);
extern u32 gCurveFishCurveQueryKey;
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
extern const f32 lbl_803E3928;
extern f32 timeDelta;

/* per-frame cap on the body's yaw turn toward the next path node */
#define CURVEFISH_MAX_YAW_TURN 0x180

int curvefish_getExtraSize(void) { return 0x120; }

typedef struct CurveFishSetup
{
    u8 pad00[8];
    f32 spawnX;
    f32 spawnY;
    f32 spawnZ;
    u8 pad14[4];
    u8 rootMotionScaleParam;
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

typedef enum CurveFishMode
{
    CURVEFISH_MODE_WAIT = 0,    /* wait setup->waitFrames game-frames */
    CURVEFISH_MODE_SPAWN = 1,   /* teleport to spawn point and bind the curve walker */
    CURVEFISH_MODE_FADE_IN = 2, /* fade alpha in over one frame-time */
    CURVEFISH_MODE_CRUISE = 3,  /* cruise along the path; reaching the end resets to wait */
} CurveFishMode;

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
    f32 distance;
    int i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 mag;
    f32 distLimit;
    f32 speedDelta;
    int targetYaw;
    int yawDelta;

    state = ((GameObject*)obj)->extra;
    setup = *(CurveFishSetup**)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    setup2 = *(CurveFishSetup**)&((GameObject*)obj)->anim.placementData;
    curveQuery = gCurveFishCurveQueryKey;

    state->phaseTimer += timeDelta;

    switch (state->mode)
    {
    default:
        return;
    case CURVEFISH_MODE_WAIT:
        {
            f32 waitTime = lbl_803E38EC * (f32)(u32)setup->waitFrames;
            if (!(state->phaseTimer >= waitTime))
            {
                return;
            }
            state->phaseTimer -= waitTime;
            state->mode = CURVEFISH_MODE_SPAWN;
        }
    case CURVEFISH_MODE_SPAWN:
        ((GameObject*)obj)->anim.localPosX = setup2->spawnX;
        ((GameObject*)obj)->anim.localPosY = setup2->spawnY;
        ((GameObject*)obj)->anim.localPosZ = setup2->spawnZ;

        firstNode = (int)(*gRomCurveInterface)->getById(
            ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
                ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ, (int*)&curveQuery, 1, -1));
        secondNode = (int)(*gRomCurveInterface)->getById(
            ((int (*)(int, int))(*gRomCurveInterface)->slot54)(firstNode, 0));
        thirdNode = (int)(*gRomCurveInterface)->getById(
            ((int (*)(int, int))(*gRomCurveInterface)->slot54)(secondNode, 0));

        if (fn_800DA980((RomCurveWalker*)state, (void*)firstNode, (void*)secondNode, (void*)thirdNode) != 0)
        {
            return;
        }
        state->mode = CURVEFISH_MODE_FADE_IN;
        state->speed = lbl_803E38F0;
    case CURVEFISH_MODE_FADE_IN:
        if (state->phaseTimer <= lbl_803E38EC)
        {
            ((GameObject*)obj)->anim.alpha =
                (u8)(int)(lbl_803E38F4 * (state->phaseTimer / lbl_803E38EC));
            return;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        state->mode = CURVEFISH_MODE_CRUISE;
    case CURVEFISH_MODE_CRUISE:
        break;
    }

    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
    {
        state->speed = lbl_803E38F8 * state->maxSpeed;
    }
    else if (fn_80296448((int)player) != 0 &&
        getXZDistance(&((GameObject*)player)->anim.localPosX, (f32*)(obj + 0xc)) <
        (f32)(u32)setup->playerRadius * (f32)(u32)setup->playerRadius)
    {
        speedDelta = lbl_803E38F8 * (f32)(u32)setup2->speedChange;
        state->speed += (speedDelta * timeDelta) / lbl_803E38FC;
        if (state->speed > (maxHitSpeed = lbl_803E38F8 * state->maxSpeed))
        {
            state->speed = maxHitSpeed;
        }
    }
    else
    {
        speedDelta = (f32)(int)randomGetRange(-setup2->speedChange,
                                              setup2->speedChange << 1);
        state->speed += (speedDelta * timeDelta) / lbl_803E38FC;
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

    if (lbl_803E38F0 != state->speed)
    {
        distLimit = state->speed * timeDelta;
        distLimit *= distLimit;
        distance = getXZDistance(&state->targetX, (f32*)(obj + 0xc));
        i = 0;
        while (distLimit > distance && i < 5)
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
                state->mode = CURVEFISH_MODE_WAIT;
                state->phaseTimer = lbl_803E38F0;
                ((GameObject*)obj)->anim.alpha = 0;
                return;
            }
        }

        dx = state->targetX - ((GameObject*)obj)->anim.localPosX;
        dy = (state->targetY + (f32)(u32)setup->targetYOffset) - ((GameObject*)obj)->anim.localPosY;
        dz = state->targetZ - ((GameObject*)obj)->anim.localPosZ;
        mag = sqrtf(dx * dx + dy * dy + dz * dz);
        dx /= mag;
        dy /= mag;
        dz /= mag;

        ((GameObject*)obj)->anim.localPosX += dx * state->speed;
        ((GameObject*)obj)->anim.localPosY += dy * state->speed;
        ((GameObject*)obj)->anim.localPosZ += dz * state->speed;

        targetYaw = getAngle(dx, dz);
        yawDelta = targetYaw - ((u16)(((GameObject*)obj)->anim.rotX));
        if (yawDelta > 0x8000)
        {
            yawDelta -= 0xffff;
        }
        if (yawDelta < -0x8000)
        {
            yawDelta += 0xffff;
        }
        if (yawDelta > CURVEFISH_MAX_YAW_TURN)
        {
            ((GameObject*)obj)->anim.rotX += CURVEFISH_MAX_YAW_TURN;
        }
        else if (yawDelta < -CURVEFISH_MAX_YAW_TURN)
        {
            ((GameObject*)obj)->anim.rotX -= CURVEFISH_MAX_YAW_TURN;
        }
        else
        {
            ((GameObject*)obj)->anim.rotX = targetYaw;
        }
    }

    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->moveStepScale, timeDelta, NULL);
    state->animTimer += timeDelta;
}

void curvefish_init(int obj, u8* setup)
{
    int state;
    u32 flags;
    state = *(int*)&((GameObject*)obj)->extra;
    flags = ((GameObject*)obj)->objectFlags;
    flags |= 0x6000;
    ((GameObject*)obj)->objectFlags = flags;
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase *
        ((f32)(u32)((CurveFishSetup*)setup)->rootMotionScaleParam / lbl_803E3928);
    ((CurveFishState*)state)->mode = CURVEFISH_MODE_SPAWN;
    ((CurveFishState*)state)->maxSpeed = (f32)(u32)setup[0x19] / lbl_803E3928;
}

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
