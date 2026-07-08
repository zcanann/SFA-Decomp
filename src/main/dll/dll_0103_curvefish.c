/*
 * curvefish (DLL 0x0103) - a fish that swims an endless loop along a ROM
 * curve path (Curve_AdvanceAlongPath), fading in on spawn and steering its
 * yaw toward the next path node each frame.
 *
 * CurveFish_update is a four-stage state machine (CurveFishState.mode):
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
 * The ObjectDescriptors for the 0x00FE..0x0103 bundle (including
 * gCurveFishObjDescriptor) live in dll_0100_trickywarp.c, whose .data split
 * range (0x80321568..0x803216B8) owns them in retail.
 */
#include "main/game_object.h"
#include "main/dll/dll_00FE_magicplant.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gameplay_runtime.h"
#include "main/objhits.h"
#include "main/frame_timing.h"
extern f32 getXZDistance(f32* a, f32* b);
extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern int playerGetFlags3F0Bit5(int obj);

/* ROM curve query key for the fish path curves; first entry of this TU's
 * .sdata2 (retail 0x803E38E8), followed by the compiler float pool. Read
 * through a volatile view in CurveFish_update so the value is not constant
 * folded away. */
const u32 gCurveFishCurveQueryKey = ROMCURVE_TYPE_CURVEFISH;

/* per-frame cap on the body's yaw turn toward the next path node */
#define CURVEFISH_MAX_YAW_TURN 0x180

int CurveFish_getExtraSize(void) { return 0x120; }

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

void CurveFish_update(int obj)
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
    curveQuery = *(volatile u32*)&gCurveFishCurveQueryKey;

    state->phaseTimer += timeDelta;

    switch (state->mode)
    {
    case CURVEFISH_MODE_WAIT:
        {
            f32 waitTime = 60.0f * (f32)(u32)setup->waitFrames;
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
        state->speed = 0.0f;
    case CURVEFISH_MODE_FADE_IN:
        if (state->phaseTimer <= 60.0f)
        {
            ((GameObject*)obj)->anim.alpha =
                (u8)(int)(255.0f * (state->phaseTimer / 60.0f));
            return;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        state->mode = CURVEFISH_MODE_CRUISE;
    case CURVEFISH_MODE_CRUISE:
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
        {
            state->speed = 2.0f * state->maxSpeed;
        }
        else if (playerGetFlags3F0Bit5((int)player) != 0 &&
            getXZDistance(&((GameObject*)player)->anim.localPosX, (f32*)(obj + 0xc)) <
            (f32)(u32)setup->playerRadius * (f32)(u32)setup->playerRadius)
        {
            speedDelta = 2.0f * (f32)(u32)setup2->speedChange;
            state->speed += (speedDelta * timeDelta) / 1000.0f;
            if (state->speed > (maxHitSpeed = 2.0f * state->maxSpeed))
            {
                state->speed = maxHitSpeed;
            }
        }
        else
        {
            speedDelta = (f32)(int)randomGetRange(-setup2->speedChange,
                                                  setup2->speedChange << 1);
            state->speed += (speedDelta * timeDelta) / 1000.0f;
            if (state->speed < 0.0f)
            {
                state->speed = 0.0f;
            }
            else if (state->speed > state->maxSpeed)
            {
                state->speed = state->maxSpeed;
            }
        }

        speedThreshold = state->maxSpeed / 4.0f;
        if (state->speed < speedThreshold)
        {
            if (((GameObject*)obj)->anim.currentMove == 0 && state->animTimer > 120.0f)
            {
                ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
                state->animTimer = 0.0f;
            }
            state->moveStepScale = 0.0075f;
        }
        else if (state->speed > 3.0f * state->maxSpeed / 4.0f)
        {
            if (((GameObject*)obj)->anim.currentMove == 0 && state->animTimer > 240.0f)
            {
                ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
                state->animTimer = 0.0f;
            }
            state->moveStepScale = 0.015f;
        }
        else
        {
            if (((GameObject*)obj)->anim.currentMove == 1 && state->animTimer > 240.0f)
            {
                ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x3c);
                state->animTimer = 0.0f;
            }
            state->moveStepScale = (0.015f * state->speed) / state->maxSpeed;
        }

        if (0.0f != state->speed)
        {
            distLimit = state->speed * timeDelta;
            distLimit *= distLimit;
            distance = getXZDistance(&state->targetX, (f32*)(obj + 0xc));
            i = 0;
            while (distLimit > distance && i < 5)
            {
                Curve_AdvanceAlongPath((RomCurveWalker*)state, 2.0f);
                distance = getXZDistance(&state->targetX, (f32*)(obj + 0xc));
                i++;
            }

            if (state->hasRouteEdge != 0)
            {
                nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot54)(state->routeCursor, 0);
                if (curveFn_800da23c((RomCurveWalker*)state, (*gRomCurveInterface)->getById(nextNode)) != 0)
                {
                    state->mode = CURVEFISH_MODE_WAIT;
                    state->phaseTimer = 0.0f;
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
    default:
        return;
    }
}

void CurveFish_init(int obj, u8* setup)
{
    int state;
    u32 flags;
    state = *(int*)&((GameObject*)obj)->extra;
    flags = ((GameObject*)obj)->objectFlags;
    flags |= 0x6000;
    ((GameObject*)obj)->objectFlags = flags;
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase *
        ((f32)(u32)((CurveFishSetup*)setup)->rootMotionScaleParam / 100.0f);
    ((CurveFishState*)state)->mode = CURVEFISH_MODE_SPAWN;
    ((CurveFishState*)state)->maxSpeed = (f32)(u32)setup[0x19] / 100.0f;
}

