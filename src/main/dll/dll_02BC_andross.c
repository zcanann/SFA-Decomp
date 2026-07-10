/*
 * andross (DLL 0x2BC) - the final Andross boss, fought from the Arwing.
 *
 * andross_update is the whole fight: it caches the player's Arwing
 * (getArwing) plus the two hand objects (0x47b78 / 0x47b6a) and the brain
 * light-anchor object (0x47dd9), then runs a two-level state machine over
 * AndrossState - an outer fightPhase (1..6) selecting the move set and an
 * inner actionState driving each animation move via ObjAnim_SetCurrentMove.
 * Each tick it tracks a swaying target position (K*sin(t) + home + clamped
 * Arwing delta), applies a spring toward it, advances the move, spawns hand
 * shots / projectiles, drives the screen distortion filter, and feeds the
 * Arwing's aim toward nearby helper objects. Fade-out and the final warp
 * (0x4e) happen once the boss-clear game bits (2/3/4) are set.
 *
 * Game bits: game bit 0xD is the attack-window flag (set/cleared around
 * phase transitions and move entry, distinct from actionState case 0xD),
 * 0xF/0x10 sequence sub-
 * moves, 0x12 the spawn cooldown, 0x108..0x10D the six random hit cues, and
 * 0x405/0x4B1/1 the clear/credits transition.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/dll_02BC_andross.h"
#include "main/dll/dll_02BD_androsshand.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"

#define GAMEBIT_ANDROSS_HIT_CUE_BASE 0x108 /* six consecutive random-hit cue bits */

#define ANDROSS_CHILD_OBJ_SPAWNED 0x819 /* cached into state->spawnedObj w/ spawnedObjLifetime */

#define ANDROSS_MAP_SHRINE 0xb /* Krazoa shrine map warped to on fight completion */

typedef struct
{
    u8 f80 : 1;
    u8 f40 : 1;
    u8 f20 : 1;
} AndrossFlagByte;

extern f32 lbl_8032C098[];
extern f32 lbl_803DC440;
extern f32 lbl_803DC444;
extern f32 lbl_803DC448;
extern f32 lbl_803DC454;
extern f32 lbl_803DC458;
extern f32 lbl_803DC45C;
extern f32 lbl_803DC468;
extern f32 gAndrossSpawnRandX;
extern f32 gAndrossSpawnRandY;
extern f32 gAndrossSpawnRandZ;
extern f32 gAndrossSpawnOffsetY;
extern f32 gAndrossSpawnOffsetZ;
extern f32 lbl_803DC488;
extern f32 lbl_803DC490;
extern f32 lbl_803DC494;
extern f32 lbl_803DC498;
extern f32 lbl_803DC49C;
extern f32 lbl_803DC4A0;
extern f32 lbl_803DC4A4;
extern f32 lbl_803DC4A8;
extern f32 lbl_803DC4AC;
extern f32 lbl_803DC4B0;
extern f32 lbl_803DC4B4;
extern f32 lbl_803DC4B8;
extern f32 gAndrossDistortPhaseStep;
extern f32 gAndrossDistortPhaseReset;
extern f32 gAndrossDistortPhase;
extern f32 lbl_803E74B8;
extern f32 lbl_803E74BC;
extern f32 lbl_803E74C0;
extern f32 lbl_803E74C4;
extern f32 lbl_803E74C8;
extern f32 gAndrossSwayAmplitudeX;
extern f32 gAndrossDistortPhaseWrap;
extern f32 gAndrossPathPosOffset;
extern f32 lbl_803E74E4;
extern f32 lbl_803E74E8;
extern f32 lbl_803E74EC;
extern f32 lbl_803E74F0;
extern f32 lbl_803E74F4;
extern f32 lbl_803E74F8;
extern f32 gAndrossSwayAmplitudeY;
extern f32 lbl_803E7500;
extern f32 lbl_803E7504;
extern f32 lbl_803E7508;
extern f32 lbl_803E750C;
extern f32 lbl_803E7510;
extern f32 lbl_803E7514;
extern f32 lbl_803E7518;
extern f32 gAndrossFadeAlphaStep;
extern f32 lbl_803E7520;
extern f32 lbl_803E7524;
extern f32 lbl_803E7528;
extern f32 lbl_803E752C;
extern f32 gAndrossFadeAlphaMax;
extern f32 lbl_803E7538;
extern f32 lbl_803E753C;
extern f32 lbl_803E7578;
extern f32 gAndrossCachedPosOffsetY;
extern f32 gAndrossCachedPosOffsetZ;
extern f32 lbl_803E7584;
extern f64 lbl_803E7540;
extern f64 lbl_803E7548;
extern f64 lbl_803E7550;
extern f64 lbl_803E7558;
extern f64 lbl_803E7560;
extern f64 lbl_803E7568;
extern f64 lbl_803E7570;
extern int animatedObjGetSeqId(int obj);
extern int gAndrossSpawnObjectIds[];
extern int lbl_803DC430;
extern int lbl_803DC434;
extern int gAndrossFlightHalfWidth;
extern int lbl_803DC43C;
extern int lbl_803DC44C;
extern int lbl_803DC450;
extern int lbl_803DC460;
extern int lbl_803DC464;
extern int lbl_803DC46C;
extern int lbl_803DC484;
extern int lbl_803DC48C;
extern int lbl_803DC4EC;
extern s16 gAndrossSwayPhaseStepX;
extern s16 gAndrossSwayPhaseStepY;
extern s16 gAndrossSwayPhaseY;
extern s16 gAndrossSwayPhaseX;
extern f32 gAndrossDistortFilterParam;
extern void turnOnDistortionFilter(f32* pos, f32 a, f32* b, f32 c);

int andross_getExtraSize(void)
{
    return 0xec;
}

int andross_getObjectTypeId(void)
{
    return 0;
}

void andross_free(int obj)
{
    fn_8006CB24(obj);
    Rcp_DisableDistortionFilter();
}

void andross_hitDetect(void)
{
}

void andross_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E74DC);
}

void andross_setPartSignal(GameObject* obj, int signal)
{
    int state;

    if ((void*)obj == NULL)
    {
        return;
    }
    state = *(int*)&(obj)->extra;
    ((AndrossState*)state)->signalFlags |= signal;
}

#pragma scheduling off
int andross_SeqFn(GameObject* obj)
{
    int state = *(int*)&(obj)->extra;
    int i;
    f32 fade;
    f32 alpha;
    int model;
    int op;

    *(f32*)(state + 0x68) = lbl_803E74D4;
    fade = ((AndrossState*)state)->fadeAlpha;
    model = *(int*)Obj_GetActiveModel((int)obj);
    i = 0;
    alpha = gAndrossAlpha255 * fade;
    for (; i < *(u8*)(model + 0xf8); i++)
    {
        op = ObjModel_GetRenderOp(model, i);
        *(s8*)(op + 0x43) = alpha;
    }
    return 0;
}

#pragma peephole off
void andross_init(int obj, u8* setup)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int i;
    int model;
    int val;

    ((AndrossState*)state)->homePosX = ((ObjPlacement*)setup)->posX;
    ((AndrossState*)state)->homePosY = ((ObjPlacement*)setup)->posY;
    ((AndrossState*)state)->homePosZ = ((ObjPlacement*)setup)->posZ;
    ((AndrossState*)state)->actionTimer = 0;
    ((AndrossState*)state)->actionState = 0;
    ((AndrossState*)state)->prevActionState = -1;
    ((AndrossState*)state)->animSpeed = gAndrossInitAnimSpeed;
    ((AndrossState*)state)->startupDelay = 5;
    ((AndrossState*)state)->fightPhase = 1;
    ((AndrossState*)state)->prevFightPhase = -1;
    ((AndrossState*)state)->targetRotX = -0x8000;
    ((GameObject*)obj)->anim.rotX = -0x8000;
    ((AndrossState*)state)->spawnCooldown = gAndrossInitSpawnCooldown;
    ((AndrossState*)state)->camOffsetAccum = lbl_803E74D4;
    ((AndrossState*)state)->springStiffness = gAndrossSpringStiffness;
    ((AndrossState*)state)->springDamping = gAndrossSpringDamping;
    ((AndrossState*)state)->handsInitialized = 1;
    ObjHits_SetTargetMask(obj, 4);
    ((GameObject*)obj)->animEventCallback = andross_SeqFn;
    fn_8006CB50();
    i = Obj_GetActiveModel(obj);
    model = *(int*)i;
    for (i = 0, val = i; i < *(u8*)(model + 0xf8); i++)
    {
        *(u8*)(ObjModel_GetRenderOp(model, i) + 0x43) = val;
    }
    mainSetBits(0xd, 0);
    unlockLevel(0, 0, 1);
}

void fn_8023A87C(GameObject* obj, int state)
{
    void* spawned;

    spawned = *(void**)&((AndrossState*)state)->effectHandle;
    if (spawned != NULL)
    {
        ((GameObject*)spawned)->anim.localPosZ -= lbl_803E74D8;
        ((AndrossState*)state)->effectLifetime -= framesThisStep;
        if (((AndrossState*)state)->effectLifetime < 0)
        {
            arwbombcoll_setLifetime((GameObject*)(((AndrossState*)state)->effectHandle), 5);
            ((AndrossState*)state)->effectLifetime = 0;
            ((AndrossState*)state)->effectHandle = 0;
        }
    }
    else
    {
        f32 cooldown = ((AndrossState*)state)->spawnCooldown;
        f32 zero = lbl_803E74D4;
        if (cooldown >= zero)
        {
            ((AndrossState*)state)->spawnCooldown = cooldown - timeDelta;
            if (((AndrossState*)state)->spawnCooldown < zero)
                fn_80239DD8(obj, state);
        }
        else if ((u32)mainGetBit(GAMEBIT_AndrossRelated0012) != 0)
        {
            ((AndrossState*)state)->spawnCooldown = (f32)(int)randomGetRange(1, 0x14);
            mainSetBits(GAMEBIT_AndrossRelated0012, 0);
        }
    }
}

int fn_8023A6A4(AndrossState* state, f32 clampRange, f32 scale, f32 zVel)
{
    f32 mag, ang;
    f32 dx, dy, dz, dist;
    int yaw;
    int result;
    f32 vel[3];

    result = 0;
    dx = state->cachedPosX - state->arwingObj->anim.localPosX;
    dy = state->cachedPosY - state->arwingObj->anim.localPosY;
    dz = state->cachedPosZ - state->arwingObj->anim.localPosZ;
    dist = sqrtf(dx * dx + dy * dy);
    yaw = (s16)getAngle(dx, dy);
    if ((s16)getAngle(dist, dz) > 0x2ee0 && dz > lbl_803DC4C0)
        result = 1;
    mag = (dist / scale < -clampRange) ? -clampRange : ((dist / scale > clampRange) ? clampRange : dist / scale);
    ang = lbl_803E74A0 * yaw / lbl_803E74A4;
    state->velX = mag * mathSinf(ang);
    state->velY = mag * mathCosf(ang);
    arwarwing_getVelocity((int)vel, (int)state->arwingObj);
    state->velX -= vel[0] * gAndrossArwingVelDamp;
    state->velY -= vel[1] * gAndrossArwingVelDamp;
    state->velZ = zVel;
    return result;
}

void andross_update(int obj)
{
    GameObject* boss;
    u8 pathAdjusted;
    u8 stateChanged;
    int work;
    u8 flag;
    AndrossState* state;
    AndrossState* moveState;
    AndrossHandState* handStateA;
    AndrossHandState* handStateB;
    GameObject* aimTarget;
    GameObject** spawnSlot;
    u8 spawnIndex;
    int ref;
    int durationBeforeStep;
    u32 val;
    f32 fc;
    f32 fval;
    s16 sval;
    int found;
    s8 bval;
    s16 randVal;
    int objId;
    u8 signals;
    f32 fa;
    f32 fb;
    f32 zero;
    s16 delayPair[2];
    SunVec3 thrustB;
    SunVec3 thrustA;
    SunVec3 thrustBArg;
    SunVec3 thrustAArg;
    SunVec3 velAdd;
    SunVec3 velArg3;
    SunVec3 velCalc3;
    SunVec3 velArg2;
    SunVec3 velCalc2;
    SunVec3 velArg1;
    SunVec3 velCalc1;
    SunVec3 velArg0;
    SunVec3 velCalc0;
    f32 camActionParam;
    f32 searchDist0;
    f32 searchDist1;
    f32 searchDist2;
    f32 searchDist3;
    f32 searchDist;
    boss = (GameObject*)obj;
    state = (AndrossState*)boss->extra;
    pathAdjusted = 0;
    stateChanged = 0;
    flag = 0;
    if (state->startupDelay != 0)
    {
        state->startupDelay -= 1;
        return;
    }
    if (state->handObjA == NULL)
    {
        found = ObjList_FindObjectById(0x47b78);
        state->handObjA = (GameObject*)found;
    }
    if (state->handObjB == NULL)
    {
        found = ObjList_FindObjectById(0x47b6a);
        state->handObjB = (GameObject*)found;
    }
    if (state->lightAnchorObj == NULL)
    {
        found = ObjList_FindObjectById(0x47dd9);
        state->lightAnchorObj = (GameObject*)found;
    }
    if (state->arwingObj == NULL)
    {
        found = getArwing();
        state->arwingObj = (GameObject*)found;
        if (state->arwingObj != NULL)
        {
            state->savedPosZ = state->arwingObj->anim.localPosZ;
            arwarwing_setFlightHalfWidth((int)state->arwingObj, gAndrossFlightHalfWidth);
        }
        else
        {
            return;
        }
    }
    for (work = 0; (u8)work < 4; work++)
    {
        spawnIndex = work;
        spawnSlot = &state->spawnObj[spawnIndex];
        if (*spawnSlot == NULL)
        {
            *spawnSlot = (GameObject*)ObjList_FindObjectById(gAndrossSpawnObjectIds[spawnIndex]);
            if (*spawnSlot != NULL)
            {
                state->spawnDelta[spawnIndex].x =
                    (*spawnSlot)->anim.localPosX - boss->anim.localPosX;
                state->spawnDelta[spawnIndex].y =
                    (*spawnSlot)->anim.localPosY - boss->anim.localPosY;
                state->spawnDelta[spawnIndex].z =
                    (*spawnSlot)->anim.localPosZ - boss->anim.localPosZ;
            }
        }
        else
        {
            (*spawnSlot)->anim.localPosX = boss->anim.localPosX + state->spawnDelta[spawnIndex].x;
            (*spawnSlot)->anim.localPosY = boss->anim.localPosY + state->spawnDelta[spawnIndex].y;
            (*spawnSlot)->anim.localPosZ = boss->anim.localPosZ + state->spawnDelta[spawnIndex].z;
        }
    }
    found = state->fightPhase;
    if (found != state->prevFightPhase)
    {
        stateChanged = 1;
    }
    state->prevFightPhase = found;
    fval = lbl_803E74D4;
    state->velX = lbl_803E74D4;
    state->velY = fval;
    state->velZ = fval;
    if ((-0x4000 < state->targetRotX) && (boss->anim.rotX < 0x4000))
    {
        pathAdjusted = 1;
    }
    ObjPath_GetPointWorldPosition(
        obj, pathAdjusted, &state->cachedPosX, &state->cachedPosY, &state->cachedPosZ, 0);
    if (pathAdjusted == 1)
    {
        fa = state->cachedPosY;
        fval = gAndrossPathPosOffset;
        state->cachedPosY = fa + fval;
        state->cachedPosZ += fval;
    }
    switch (state->fightPhase)
    {
    case 1:
        if (stateChanged)
        {
            if (state->handsInitialized != 0)
            {
                state->handsInitialized = 0;
            }
            else
            {
                androsshand_setState(state->handObjA, 2, 1);
                androsshand_setState(state->handObjB, 2, 1);
            }
            state->hitsRemaining0 = 10;
            state->hitsRemaining1 = 10;
            state->hitsRemaining2 = 10;
        }
        if (state->actionPending != 0)
        {
            switch (state->actionState)
            {
            default:
            case 3:
            case 0x17:
                state->actionState = 0;
                break;
            case 0:
                state->actionState = 1;
                break;
            case 0x16:
                if (state->arwingFlightActive != 0)
                {
                    state->actionState = 0x17;
                }
                else
                {
                    state->actionState = 0;
                }
                break;
            }
            state->actionPending = 0;
        }
        break;
    case 2:
        if ((stateChanged) && (state->signalFlags &= ~0x6,
                               state->actionState == 0x16))
        {
            androsshand_setState(state->handObjA, 1, 1);
            androsshand_setState(state->handObjB, 1, 1);
        }
        if (state->actionPending != 0)
        {
            switch (state->actionState)
            {
            default:
            case 5:
            case 0x16:
                state->actionState = 6;
                break;
            case 6:
                state->actionState = 7;
                break;
            case 7:
                state->actionState = 10;
                break;
            case 10:
                state->actionState = 0x12;
                break;
            case 0x14:
                state->actionState = 0xb;
                break;
            case 0x11:
                state->actionState = 0x16;
                state->targetRotX = 0x8000;
                state->fightPhase--;
            }
            state->actionPending = 0;
        }
        break;
    case 3:
        if (stateChanged)
        {
            state->hitsRemaining0 = 0xf;
            state->hitsRemaining1 = 0xf;
            state->hitsRemaining2 = 0xf;
            state->actionState = 0;
            state->attackCycleCount = 0;
        }
        if (state->actionPending != 0)
        {
            switch (state->actionState)
            {
            default:
            case 0:
                state->actionState = 1;
                break;
            case 3:
                state->actionState = 4;
                break;
            case 4:
                state->attackCycleCount++;
                if (state->attackCycleCount > 3)
                {
                    state->fightPhase--;
                    state->actionState = 0x16;
                    state->targetRotX = 0;
                }
                else
                {
                    state->actionState = 0;
                }
                break;
            }
            state->actionPending = 0;
        }
        break;
    case 4:
        if (state->actionPending != 0)
        {
            switch (state->actionState)
            {
            default:
            case 5:
            case 0x16:
                state->actionState = 6;
                break;
            case 6:
                state->actionState = 7;
                break;
            case 7:
                state->actionState = 10;
                break;
            case 10:
                state->actionState = 0x12;
                break;
            case 0x14:
                state->actionState = 0xb;
                break;
            case 0xf:
                state->actionState = 9;
                break;
            case 9:
                state->actionState = 8;
                break;
            case 0x11:
                state->actionState = 0x18;
            }
            state->actionPending = 0;
        }
        break;
    case 5:
        if (stateChanged)
        {
            state->actionState = 0xd;
            state->actionToggle = 0;
        }
        if (state->actionPending != 0)
        {
            switch (state->actionState)
            {
            default:
            case 0x1b:
                state->unkB1[0] = 3;
            case 0xf:
                state->actionState = 0x12;
                state->actionToggle = 0;
                break;
            case 0x14:
                switch (state->actionToggle)
                {
                case 0:
                    state->actionState = 0x15;
                    break;
                case 1:
                    state->actionState = 0xb;
                    break;
                }
                state->actionToggle ^= 1;
                break;
            case 0x15:
                state->actionState = 0x12;
                break;
            case 0x11:
                state->actionState = 0x18;
                break;
            case 0x19:
                state->fightPhase = 6;
                break;
            case 0x1a:
                state->actionState = 0x1b;
            }
            state->actionPending = 0;
        }
        break;
    case 6:
        if (stateChanged)
        {
            state->actionState = 0x1c;
            state->actionToggle = 0;
        }
        break;
    }
    found = state->actionState;
    if (found != state->prevActionState)
    {
        flag += 1;
    }
    state->prevActionState = found;
    switch (state->actionState)
    {
    case 0:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[0];
            if (state->fightPhase == 1)
            {
                state->durationTimer = lbl_803E74E4;
            }
            else
            {
                state->durationTimer = lbl_803E74E8;
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->durationTimer -= timeDelta;
        if (state->durationTimer < lbl_803E74D4)
        {
            state->actionPending = 1;
        }
        val = state->hitsRemaining0;
        val = val + state->hitsRemaining1;
        val = val + state->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 1:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0xc, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[12];
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            state->actionState = 2;
            state->actionPending = 0;
        }
        val = state->hitsRemaining0;
        val = val + state->hitsRemaining1;
        val = val + state->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 2:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0xe, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[14];
            state->durationTimer = lbl_803E74F0;
            state->actionTimer = 0xffff;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_roar1);
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0)
        {
            fn_8023A268(obj, (int)state, 0);
            state->actionTimer = lbl_803DC43C;
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < lbl_803E74D4)
        {
            state->actionState = 3;
            state->actionPending = 0;
        }
        val = state->hitsRemaining0;
        val = val + state->hitsRemaining1;
        val = val + state->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 3:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0xd, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[13];
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            state->actionPending = 1;
        }
        break;
    case 4:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[0];
            mainSetBits(0xd, 1);
            state->durationTimer = lbl_803E7504;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->durationTimer -= timeDelta;
        if (state->durationTimer < lbl_803E74D4)
        {
            state->actionPending = 1;
            mainSetBits(0xd, 0);
        }
        val = state->hitsRemaining0;
        val = val + state->hitsRemaining1;
        val = val + state->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 0x15:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[0];
            mainSetBits(0xd, 1);
            state->durationTimer = lbl_803E7504;
        }
        for (ref = 0; (u8)ref < 6; ref++)
        {
            if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
            {
                state->timer = 0x3c;
                break;
            }
        }
        if (ref == 6)
        {
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->durationTimer -= timeDelta;
        if (state->durationTimer < lbl_803E74D4)
        {
            state->actionPending = 1;
            mainSetBits(0xd, 0);
        }
        break;
    case 6:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[0];
            androsshand_setState(state->handObjB, 4, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E7508) ? lbl_803E7508 : ((fb > lbl_803E750C) ? lbl_803E750C : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX = (lbl_803E74E8 * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        flag = 0;
        found = *(int*)&boss->extra;
        signals = *(u8*)(found + 0xad);
        if ((signals & 1) != 0)
        {
            *(u8*)(found + 0xad) = signals & ~1;
            flag = 1;
        }
        if (flag != 0)
        {
            state->actionPending = 1;
        }
        break;
    case 7:
        if (flag)
        {
            androsshand_setState(state->handObjA, 4, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E7508) ? lbl_803E7508 : ((fb > lbl_803E750C) ? lbl_803E750C : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX = (lbl_803E74E8 * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        flag = 0;
        found = *(int*)&boss->extra;
        signals = *(u8*)(found + 0xad);
        if ((signals & 1) != 0)
        {
            *(u8*)(found + 0xad) = signals & ~1;
            flag = 1;
        }
        if (flag != 0)
        {
            state->actionPending = 1;
        }
        break;
    case 9:
        if (flag)
        {
            androsshand_setState(state->handObjA, 6, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        flag = 0;
        found = *(int*)&boss->extra;
        signals = *(u8*)(found + 0xad);
        if ((signals & 1) != 0)
        {
            *(u8*)(found + 0xad) = signals & ~1;
            flag = 1;
        }
        if (flag != 0)
        {
            state->actionPending = 1;
        }
        break;
    case 8:
        if (flag)
        {
            androsshand_setState(state->handObjB, 6, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        flag = 0;
        found = *(int*)&boss->extra;
        signals = *(u8*)(found + 0xad);
        if ((signals & 1) != 0)
        {
            *(u8*)(found + 0xad) = signals & ~1;
            flag = 1;
        }
        if (flag != 0)
        {
            state->actionPending = 1;
        }
        break;
    case 10:
        if ((state->signalFlags & 6) == 6)
        {
            state->fightPhase++;
            if (state->fightPhase < 5)
            {
                Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
                state->actionState = 0x16;
                state->targetRotX = 0x8000;
            }
        }
        else
        {
            gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
            gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
            fb = (state->arwingObj->anim.localPosX - state->homePosX);
            fa = (state->arwingObj->anim.localPosY - state->homePosY);
            fc = (fb < lbl_803E7508) ? lbl_803E7508 : ((fb > lbl_803E750C) ? lbl_803E750C : fb);
            fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
            fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
            state->targetPosX = (lbl_803E74E8 * fa + (float)(state->homePosX + fc));
            fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
            state->targetPosY =
                (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
            state->targetPosZ = state->homePosZ;
            if (flag)
            {
                androsshand_setState(state->handObjA, 5, 0);
                androsshand_setState(state->handObjB, 5, 0);
            }
            flag = 0;
            found = *(int*)&boss->extra;
            signals = *(u8*)(found + 0xad);
            if ((signals & 1) != 0)
            {
                *(u8*)(found + 0xad) = signals & ~1;
                flag = 1;
            }
            if (flag != 0)
            {
                state->actionPending = 1;
            }
        }
        break;
    case 0xb:
    case 0xd:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[1];
            if (state->fightPhase < 5)
            {
                androsshand_setState(state->handObjA, 0, 0);
                androsshand_setState(state->handObjB, 0, 0);
            }
            else
            {
                androsshand_setState(state->handObjA, 9, 1);
                androsshand_setState(state->handObjB, 9, 1);
                state->signalFlags |= 6;
            }
        }
        if ((state->fightPhase == 5) && (state->actionState == 0xb))
        {
            for (ref = 0; (u8)ref < 6; ref++)
            {
                if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    break;
                }
            }
            if (ref == 6)
            {
                state->timer -= framesThisStep;
                if (state->timer <= 0)
                {
                    ref = randomGetRange(0, 5);
                    mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                    state->timer = 0x3c;
                }
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E7510) ? lbl_803E7510 : ((fb > gAndrossSwayAmplitudeY) ? gAndrossSwayAmplitudeY : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeY * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY = (lbl_803E7514 * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            switch (state->actionState)
            {
            default:
            case 0xb:
                state->actionState = 0xc;
                break;
            case 0xd:
                state->actionState = 0xe;
                break;
            }
        }
        fval = lbl_803E74B8 * boss->anim.currentMoveProgress;
        if (fval < lbl_803E74B8)
        {
            fc = -(lbl_803E74C0 * (lbl_803E74C4 * fval) - lbl_803E74BC);
            if (fval < lbl_803E74C8)
            {
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
            }
        }
        else
        {
            fc = gAndrossSwayAmplitudeX;
        }
        fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
        gAndrossDistortPhase = fval;
        if (fval > gAndrossDistortPhaseWrap)
        {
            gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
        }
        turnOnDistortionFilter(&state->cachedPosX, fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        break;
    case 0xe:
        fval = lbl_803E74B8 * boss->anim.currentMoveProgress + lbl_803E74B8;
        if (fval < lbl_803E74B8)
        {
            fc = -(lbl_803E74C0 * (lbl_803E74C4 * fval) - lbl_803E74BC);
            if (fval < lbl_803E74C8)
            {
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
            }
        }
        else
        {
            fc = gAndrossSwayAmplitudeX;
        }
        fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
        gAndrossDistortPhase = fval;
        if (fval > gAndrossDistortPhaseWrap)
        {
            gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
        }
        turnOnDistortionFilter(&state->cachedPosX, fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[2];
            state->unkB1[0] = 0;
            mainSetBits(0x10, 0);
            state->actionTimer = lbl_803DC44C;
            state->durationTimer = lbl_803E74D4;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7508) ? lbl_803E7508 : ((fa > lbl_803E750C) ? lbl_803E750C : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeY * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY = (lbl_803E7514 * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        fn_8023A6A4(state, lbl_803DC440, lbl_803DC444, lbl_803DC448);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_missileloop);
        if ((state->actionTimer != 0) &&
            (state->actionTimer -= framesThisStep, state->actionTimer <= 0))
        {
            state->actionTimer = 0;
            mainSetBits(0xf, 1);
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < lbl_803E74D4)
        {
            fn_80239FCC(obj, (int)state);
            state->durationTimer += (f32)(lbl_803DC450);
        }
        fn_80239EAC(obj, (int)state);
        if ((u32)mainGetBit(0x10) != 0)
        {
            mainSetBits(0x10, 0);
            state->actionState = 0x1a;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossDistortPhaseWrap)
            {
                gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
            }
            turnOnDistortionFilter(&state->cachedPosX, lbl_803E74BC, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    case 0xc:
        fval = lbl_803E74B8 * boss->anim.currentMoveProgress + lbl_803E74B8;
        if (fval < lbl_803E74B8)
        {
            fc = -(lbl_803E74C0 * (lbl_803E74C4 * fval) - lbl_803E74BC);
            if (fval < lbl_803E74C8)
            {
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
            }
        }
        else
        {
            fc = gAndrossSwayAmplitudeX;
        }
        fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
        gAndrossDistortPhase = fval;
        if (fval > gAndrossDistortPhaseWrap)
        {
            gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
        }
        turnOnDistortionFilter(&state->cachedPosX, fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[2];
            if (state->fightPhase < 5)
            {
                state->unkB1[0] = 1;
            }
            state->actionTimer = lbl_803DC460;
            state->durationTimer = lbl_803E74D4;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_missileloop);
        if (state->fightPhase == 5)
        {
            for (ref = 0; (u8)ref < 6; ref++)
            {
                if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    break;
                }
            }
            if (ref == 6)
            {
                state->timer -= framesThisStep;
                if (state->timer <= 0)
                {
                    ref = randomGetRange(0, 5);
                    mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                    state->timer = 0x3c;
                }
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74F4) ? lbl_803E74F4 : ((fb > lbl_803E74F8) ? lbl_803E74F8 : fb);
        fb = (fa < lbl_803E7510) ? lbl_803E7510 : ((fa > gAndrossSwayAmplitudeY) ? gAndrossSwayAmplitudeY : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeY * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY = (lbl_803E7514 * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        bval = fn_8023A6A4(state, lbl_803DC454, lbl_803DC458, lbl_803DC45C);
        if (bval != 0)
        {
            state->actionState = 0xf;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossDistortPhaseWrap)
            {
                gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
            }
            turnOnDistortionFilter(&state->cachedPosX, lbl_803E74BC, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < lbl_803E74D4)
        {
            fn_80239FCC(obj, (int)state);
            state->durationTimer += (f32)(lbl_803DC464);
        }
        fn_80239EAC(obj, (int)state);
        if (state->hitReactionFlag != 0)
        {
            if (state->fightPhase == 5)
            {
                state->actionState = 0x19;
            }
            else
            {
                state->actionState = 0xf;
            }
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossDistortPhaseWrap)
            {
                gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
            }
            turnOnDistortionFilter(&state->cachedPosX, lbl_803E74BC, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        else
        {
            if (state->arwingObj->anim.localPosZ > state->cachedPosZ)
            {
                state->actionState = 0x10;
                state->arwingFlightActive = 1;
                state->arwingObj->anim.localPosZ = state->cachedPosZ;
                state->velZ = lbl_803E74D4;
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
                fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
                gAndrossDistortPhase = fval;
                if (fval > gAndrossDistortPhaseWrap)
                {
                    gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
                }
                turnOnDistortionFilter(&state->cachedPosX, lbl_803E74BC, &gAndrossDistortFilterParam,
                                       gAndrossDistortPhase);
                Rcp_DisableDistortionFilter();
                break;
            }
        }
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0)
        {
            state->actionState = 0xf;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossDistortPhaseWrap)
            {
                gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
            }
            turnOnDistortionFilter(&state->cachedPosX, lbl_803E74BC, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    case 0xf:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0x10, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[16];
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E7500) ? lbl_803E7500 : ((fb > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX = (lbl_803E74E8 * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            state->actionPending = 1;
        }
        break;
    case 0x10:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0x10, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_803E7518;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        zero = lbl_803E74D4;
        fc = (fb < zero) ? zero : ((fb > zero) ? zero : fb);
        zero = *(f32*)&lbl_803E74D4;
        fb = (fa < zero) ? zero : ((fa > zero) ? zero : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX = (lbl_803E74D4 * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY = (lbl_803E74D4 * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        fc = state->cachedPosX - state->arwingObj->anim.localPosX;
        velCalc3.x = fc * lbl_803DC468;
        fc = state->cachedPosY - state->arwingObj->anim.localPosY;
        velCalc3.y = fc * lbl_803DC468;
        fc = state->cachedPosZ - state->arwingObj->anim.localPosZ;
        velCalc3.z = fc * lbl_803DC468;
        velArg3 = velCalc3;
        arwarwing_setVelocity((int)state->arwingObj, (int)&velArg3);
        fval = (lbl_803E74EC > -(lbl_803E74B0 * timeDelta - state->camOffsetAccum))
                   ? lbl_803E74EC
                   : -(lbl_803E74B0 * timeDelta - state->camOffsetAccum);
        state->camOffsetAccum = fval;
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            *(s16*)(state->arwingObj + 6) = *(s16*)(state->arwingObj + 6) | 0x4000;
            state->actionState = 0x11;
        }
        break;
    case 0x11:
        if (flag)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_and_falcoflyby);
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0x15, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[21];
            arwarwing_addHealth((int)state->arwingObj, 0xfffffffc);
        }
        fval = (lbl_803E74EC > -(lbl_803E74B0 * timeDelta - state->camOffsetAccum))
                   ? lbl_803E74EC
                   : -(lbl_803E74B0 * timeDelta - state->camOffsetAccum);
        state->camOffsetAccum = fval;
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        zero = lbl_803E74D4;
        fc = (fb < zero) ? zero : ((fb > zero) ? zero : fb);
        zero = *(f32*)&lbl_803E74D4;
        fb = (fa < zero) ? zero : ((fa > zero) ? zero : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX = (lbl_803E74D4 * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY = (lbl_803E74D4 * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            state->actionPending = 1;
        }
        break;
    case 0x12:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0x12, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[18];
            androsshand_setState(state->handObjA, 0, 0);
            androsshand_setState(state->handObjB, 0, 0);
            if ((state->fightPhase == 5) && (state->actionToggle != 0))
            {
                mainSetBits(0xe, 1);
            }
        }
        state->fadeAlpha -= gAndrossFadeAlphaStep;
        fval = (lbl_803E74D4 > state->fadeAlpha) ? lbl_803E74D4 : state->fadeAlpha;
        state->fadeAlpha = fval;
        fc = state->fadeAlpha;
        ref = *(int*)Obj_GetActiveModel(obj);
        work = 0;
        fval = gAndrossAlpha255 * fc;
        for (; work < *(u8*)(ref + 0xf8); work++)
        {
            found = ObjModel_GetRenderOp(ref, work);
            *(s8*)(found + 0x43) = fval;
        }
        if ((state->fightPhase == 5) && (state->actionToggle == 0))
        {
            for (ref = 0; (u8)ref < 6; ref++)
            {
                if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    break;
                }
            }
            if (ref == 6)
            {
                state->timer -= framesThisStep;
                if (state->timer <= 0)
                {
                    ref = randomGetRange(0, 5);
                    mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                    state->timer = 0x3c;
                }
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX = (lbl_803E74E8 * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            state->actionState = 0x13;
        }
        break;
    case 0x13:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[19];
            if (state->fightPhase == 5)
            {
                state->durationTimer = lbl_803E74A8;
            }
            else
            {
                state->durationTimer = lbl_803E74F0;
            }
            state->actionTimer = 0xffff;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_spitout);
        if ((state->fightPhase == 5) && (state->actionToggle == 0))
        {
            for (ref = 0; (u8)ref < 6; ref++)
            {
                if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    break;
                }
            }
            if (ref == 6)
            {
                state->timer -= framesThisStep;
                if (state->timer <= 0)
                {
                    ref = randomGetRange(0, 5);
                    mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                    state->timer = 0x3c;
                }
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E7520) ? lbl_803E7520 : ((fb > lbl_803E74A8) ? lbl_803E74A8 : fb);
        fb = (fa < lbl_803E7524) ? lbl_803E7524 : ((fa > lbl_803E7528) ? lbl_803E7528 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX = (lbl_803E74E8 * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->actionTimer -= framesThisStep;
        durationBeforeStep = (int)state->durationTimer;
        state->durationTimer -= framesThisStep;
        if (state->fightPhase == 5)
        {
            delayPair[0] = 300;
            delayPair[1] = 600;
        }
        else
        {
            delayPair[0] = 0x122;
            delayPair[1] = 0x28;
        }
        for (ref = 0; (u8)ref < 2; ref++)
        {
            if ((((state->spawnedObj == NULL) &&
                  (state->actionTimer <= delayPair[(u8)ref])) &&
                 ((short)durationBeforeStep > delayPair[(u8)ref])) &&
                (Obj_IsLoadingLocked() != 0))
            {
                found = Obj_AllocObjectSetup(0x24, ANDROSS_CHILD_OBJ_SPAWNED);
                *(f32*)&((AndrossState*)found)->handObjB = state->cachedPosX;
                *(f32*)&((AndrossState*)found)->lightAnchorObj = state->cachedPosY;
                *(f32*)&((AndrossState*)found)->effectHandle = state->cachedPosZ;
                *(u8*)(found + 4) = 1;
                *(u8*)(found + 5) = 1;
                ((AndrossState*)found)->unk20 = 0xffff;
                found = ((int (*)(int, int))loadObjectAtObject)(obj, found);
                state->spawnedObj = (GameObject*)found;
                if (state->spawnedObj != NULL)
                {
                    state->spawnedObj->anim.alpha = 0xff;
                    state->spawnedObj->anim.pad37[0] = 0xff;
                    state->spawnedObjLifetime = lbl_803DC4EC;
                }
            }
        }
        if (state->actionTimer < 0)
        {
            fn_8023A168(obj, (int)state);
            state->actionTimer = lbl_803DC46C;
        }
        if (state->durationTimer < lbl_803E74D4)
        {
            state->actionState = 0x14;
        }
        break;
    case 0x14:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0x14, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[20];
        }
        if ((state->fightPhase == 5) && (state->actionToggle == 0))
        {
            for (ref = 0; (u8)ref < 6; ref++)
            {
                if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    break;
                }
            }
            if (ref == 6)
            {
                state->timer -= framesThisStep;
                if (state->timer <= 0)
                {
                    ref = randomGetRange(0, 5);
                    mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                    state->timer = 0x3c;
                }
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E752C) ? lbl_803E752C : ((fa > lbl_803E74E8) ? lbl_803E74E8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(state->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            state->actionPending = 1;
        }
        break;
    case 0x19:
    case 0x1a:
        if (flag)
        {
            Sfx_PlayFromObject(obj, SFXTRIG__UNK_832);
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[4];
        }
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            state->actionPending = 1;
        }
        break;
    case 0x1b:
        if (flag)
        {
            mainSetBits(0x10, 0);
            state->actionTimer = 0x1e;
            arwarwing_resetFlightState(state->arwingObj);
            state->arwingObj->anim.localPosZ = state->savedPosZ;
            state->camOffsetAccum = lbl_803E74D4;
        }
        state->targetPosX = state->homePosX;
        state->targetPosY = state->homePosY;
        state->targetPosZ = state->homePosZ;
        if (((u32)mainGetBit(0x10) != 0) && (state->actionTimer-- == 0))
        {
            mainSetBits(0x10, 0);
            state->actionPending = 1;
        }
        break;
    case 0x1c:
        if (flag)
        {
            androssbrain_setState(state->lightAnchorObj, 1, 0);
            ObjHits_DisableObject(obj);
            state->actionTimer = 0x3c;
            state->durationTimer = lbl_803E74D8;
            state->targetPosX = state->homePosX;
            state->targetPosY = state->homePosY;
            state->targetPosZ = state->homePosZ;
            fval = lbl_803E74D4;
            boss->anim.velocityX = lbl_803E74D4;
            boss->anim.velocityY = fval;
            boss->anim.velocityZ = fval;
            state->springStiffness = lbl_803E74C8;
            state->springDamping = gAndrossSpringDamping;
        }
        state->fadeAlpha += gAndrossFadeAlphaStep;
        fval = (gAndrossFadeAlphaMax < state->fadeAlpha) ? gAndrossFadeAlphaMax
                                                                          : state->fadeAlpha;
        state->fadeAlpha = fval;
        for (ref = 0; (u8)ref < 6; ref++)
        {
            if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
            {
                state->timer = 0x3c;
                break;
            }
        }
        if (ref == 6)
        {
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        }
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0)
        {
            state->durationTimer -= lbl_803E74DC;
            if (state->durationTimer < lbl_803E74D4)
            {
                state->actionToggle += 1;
                if (state->actionToggle > 3)
                {
                    state->fightPhase = 5;
                    state->prevFightPhase = 5;
                    state->actionToggle = 0;
                    state->actionState = 0x12;
                    androssbrain_setState(state->lightAnchorObj, 0, 0);
                    ObjHits_EnableObject(obj);
                }
                else
                {
                    state->actionState = 0x1d;
                }
            }
            else
            {
                randVal = randomGetRange(0x14, 0x1e);
                state->actionTimer = randVal;
                state->targetPosX =
                    (f32)(int)randomGetRange((int)-gAndrossSpawnRandX, gAndrossSpawnRandX) +
                    state->homePosX;
                state->targetPosY =
                    (f32)(int)randomGetRange((int)-gAndrossSpawnRandY, gAndrossSpawnRandY) +
                    state->homePosY;
                state->targetPosZ =
                    (f32)(int)randomGetRange((int)-gAndrossSpawnRandZ, gAndrossSpawnRandZ) +
                    state->homePosZ;
            }
        }
        if ((state->signalFlags & 8) != 0)
        {
            arwingHudSetVisible(2);
            mainSetBits(1, 1);
            mainSetBits(0x4b1, 1);
            state->actionState = 0x1e;
            unlockLevel(0, 0, 1);
            objId = mapGetDirIdx(ANDROSS_MAP_SHRINE);
            mapUnload(objId, 0x20000000);
            Music_Trigger(MUSICTRIG_Mound_Music, 0);
        }
        fc = state->fadeAlpha;
        ref = *(int*)Obj_GetActiveModel(obj);
        work = 0;
        fval = gAndrossAlpha255 * fc;
        for (; work < *(u8*)(ref + 0xf8); work++)
        {
            found = ObjModel_GetRenderOp(ref, work);
            *(s8*)(found + 0x43) = fval;
        }
        break;
    case 0x1d:
        if (flag)
        {
            androssbrain_setState(state->lightAnchorObj, 1, 0);
            ObjHits_DisableObject(obj);
            state->actionTimer = lbl_803DC484;
            state->targetPosX = state->arwingObj->anim.localPosX;
            state->targetPosY = state->arwingObj->anim.localPosY + gAndrossSpawnOffsetY;
            state->targetPosZ = state->arwingObj->anim.localPosZ + gAndrossSpawnOffsetZ;
            fval = lbl_803E74D4;
            boss->anim.velocityX = lbl_803E74D4;
            boss->anim.velocityY = fval;
            boss->anim.velocityZ = fval;
            Sfx_PlayFromObject(obj,
                               randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
        }
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0)
        {
            state->actionState = 0x1c;
        }
        break;
    case 0x16:
        if (flag)
        {
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[0];
        }
        if (state->arwingFlightActive != 0)
        {
            fc = state->cachedPosX - state->arwingObj->anim.localPosX;
            velCalc2.x = fc * lbl_803DC488;
            fc = state->cachedPosY - state->arwingObj->anim.localPosY;
            velCalc2.y = fc * lbl_803DC488;
            fc = state->cachedPosZ - state->arwingObj->anim.localPosZ;
            velCalc2.z = fc * lbl_803DC488;
            velArg2 = velCalc2;
            arwarwing_setVelocity((int)state->arwingObj, (int)&velArg2);
            fval = (lbl_803E7538 > -(lbl_803E753C * timeDelta - state->camOffsetAccum))
                       ? lbl_803E7538
                       : -(lbl_803E753C * timeDelta - state->camOffsetAccum);
            state->camOffsetAccum = fval;
        }
        sval = state->targetRotX - (u16)boss->anim.rotX;
        if (0x8000 < sval)
        {
            sval = sval - 0xffff;
        }
        if (sval < -0x8000)
        {
            sval = sval + 0xffff;
        }
        ref = sval;
        if (ref < 0)
        {
            ref = -ref;
        }
        if (ref < 2000)
        {
            handStateA = (AndrossHandState*)state->handObjA->extra;
            handStateB = (AndrossHandState*)state->handObjB->extra;
            bval = handStateA->handState;
            if ((((bval != 2) && (bval != 1)) &&
                 (bval = handStateB->handState, bval != 2)) &&
                (bval != 1))
            {
                state->actionPending = 1;
            }
        }
        break;
    case 5:
        handStateA = (AndrossHandState*)state->handObjA->extra;
        handStateB = (AndrossHandState*)state->handObjB->extra;
        if (flag)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_drak_roar1);
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0x16, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[22];
            ((AndrossFlagByte*)&state->soundEventFlags)->f80 = 0;
            ((AndrossFlagByte*)&state->soundEventFlags)->f40 = 0;
        }
        fc = boss->anim.currentMoveProgress;
        if (fc < lbl_803E7540)
        {
            fc = mathSinf(
                ((lbl_803E74A0 * (float)(lbl_803E7548 * (lbl_803E7550 * (fc / lbl_803E7540)))) / lbl_803E74A4));
            state->targetPosZ = (lbl_803E74A8 * fc + state->homePosZ);
        }
        else
        {
            fc = mathSinf(((lbl_803E74A0 * (float)(lbl_803E7548 * (lbl_803E7558 * ((fc - lbl_803E7540) / lbl_803E7560) +
                                                                   lbl_803E7550))) /
                           lbl_803E74A4));
            state->targetPosZ = ((f32)(lbl_803DC48C)*fc + state->homePosZ);
        }
        if ((boss->anim.currentMoveProgress > lbl_803E7568) &&
            ((state->soundEventFlags >> 6 & 1) == 0u))
        {
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
            ((AndrossFlagByte*)&state->soundEventFlags)->f40 = 1;
        }
        if ((boss->anim.currentMoveProgress > lbl_803E7570) &&
            (((AndrossFlagByte*)&state->soundEventFlags)->f80 == 0))
        {
            Sfx_PlayFromObject(obj, SFXTRIG_and_laugh);
            ((AndrossFlagByte*)&state->soundEventFlags)->f80 = 1;
        }
        bval = handStateA->handState;
        if ((((bval != 2) && (bval != 1)) &&
             (bval = handStateB->handState, bval != 2)) &&
            (bval != 1))
        {
            if (boss->anim.currentMoveProgress >= lbl_803E74DC)
            {
                state->actionPending = 1;
            }
            else if (boss->anim.currentMoveProgress > lbl_803E7568)
            {
                state->targetRotX = 0;
                androsshand_setState(state->handObjA, 1,
                                     (u8)((state->fightPhase == 4) + 1));
                androsshand_setState(state->handObjB, 1,
                                     (u8)((state->fightPhase == 4) + 1));
                state->signalFlags &= ~0x6;
            }
        }
        break;
    case 0x17:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 3, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[3];
            state->soundTimer = lbl_803E74D4;
            ((AndrossFlagByte*)&state->soundEventFlags)->f20 = 0;
        }
        state->soundTimer += timeDelta;
        if ((state->soundTimer > lbl_803E7578) &&
            ((state->soundEventFlags >> 5 & 1) == 0u))
        {
            Sfx_PlayFromObject(obj, SFXTRIG_drak_pain1);
            ((AndrossFlagByte*)&state->soundEventFlags)->f20 = 1;
        }
        if (boss->anim.currentMoveProgress <= lbl_803DC490)
        {
            state->cachedPosX = boss->anim.localPosX;
            state->cachedPosY = boss->anim.localPosY - gAndrossCachedPosOffsetY;
            state->cachedPosZ = boss->anim.localPosZ - gAndrossCachedPosOffsetZ;
            fc = state->cachedPosX - state->arwingObj->anim.localPosX;
            velCalc1.x = fc * lbl_803DC494;
            fc = state->cachedPosY - state->arwingObj->anim.localPosY;
            velCalc1.y = fc * lbl_803DC494;
            fc = state->cachedPosZ - state->arwingObj->anim.localPosZ;
            velCalc1.z = fc * lbl_803DC494;
            velArg1 = velCalc1;
            arwarwing_setVelocity((int)state->arwingObj, (int)&velArg1);
        }
        else
        {
            fc = (state->savedPosZ - state->arwingObj->anim.localPosZ);
            fval = (lbl_803E74D4 < lbl_803E753C * timeDelta + state->camOffsetAccum)
                       ? lbl_803E74D4
                       : lbl_803E753C * timeDelta + state->camOffsetAccum;
            state->camOffsetAccum = fval;
            state->arwingFlightActive = 0;
            *(s16*)(state->arwingObj + 6) = *(s16*)(state->arwingObj + 6) & ~0x4000;
            ref = (int)((f32)(s16)arwarwing_getRotY((int)state->arwingObj) + fc * lbl_803DC49C);
            arwarwing_setRotY((int)state->arwingObj, ref);
            thrustB.x = lbl_803E74D4;
            thrustB.y = lbl_803E74D4;
            thrustB.z = (float)(fc * lbl_803DC498);
            thrustBArg = thrustB;
            arwarwing_setVelocity((int)state->arwingObj, (int)&thrustBArg);
        }
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            state->actionPending = 1;
        }
        break;
    case 0x18:
        if (flag)
        {
            moveState = (AndrossState*)boss->extra;
            ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E74D4, 0);
            moveState->animSpeed = lbl_8032C098[17];
            ((AndrossFlagByte*)&state->soundEventFlags)->f20 = 0;
        }
        if (boss->anim.currentMoveProgress <= lbl_803DC4A0)
        {
            fc = state->cachedPosX - state->arwingObj->anim.localPosX;
            velCalc0.x = fc * lbl_803DC4A4;
            fc = state->cachedPosY - state->arwingObj->anim.localPosY;
            velCalc0.y = fc * lbl_803DC4A4;
            fc = state->cachedPosZ - state->arwingObj->anim.localPosZ;
            velCalc0.z = fc * lbl_803DC4A4;
            velArg0 = velCalc0;
            arwarwing_setVelocity((int)state->arwingObj, (int)&velArg0);
        }
        else
        {
            fc = (state->savedPosZ - state->arwingObj->anim.localPosZ);
            fval = (lbl_803E74D4 < lbl_803E7514 * timeDelta + state->camOffsetAccum)
                       ? lbl_803E74D4
                       : lbl_803E7514 * timeDelta + state->camOffsetAccum;
            state->camOffsetAccum = fval;
            state->arwingFlightActive = 0;
            *(s16*)(state->arwingObj + 6) = *(s16*)(state->arwingObj + 6) & ~0x4000;
            ref = (int)((f32)(s16)arwarwing_getRotY((int)state->arwingObj) + fc * lbl_803DC4AC);
            arwarwing_setRotY((int)state->arwingObj, ref);
            thrustA.x = lbl_803E74D4;
            thrustA.y = lbl_803E74D4;
            thrustA.z = (float)(fc * lbl_803DC4A8);
            thrustAArg = thrustA;
            arwarwing_setVelocity((int)state->arwingObj, (int)&thrustAArg);
            if ((state->soundEventFlags >> 5 & 1) == 0u)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_drak_pain1);
                ((AndrossFlagByte*)&state->soundEventFlags)->f20 = 1;
            }
        }
        if (boss->anim.currentMoveProgress >= lbl_803E74DC)
        {
            state->actionPending = 1;
        }
        break;
    case 0x1e:
        ref = mainGetBit(2);
        if ((((u32)ref != 0) || (ref = mainGetBit(3), (u32)ref != 0)) || (ref = mainGetBit(4), (u32)ref != 0))
        {
            mainSetBits(GAMEBIT_WM_ObjGroups, 0);
            (*gMapEventInterface)->setMapAct(ANDROSS_MAP_SHRINE, 7);
            unlockLevel(0, 0, 1);
            loadMapAndParent(mapGetDirIdx(ANDROSS_MAP_SHRINE));
            objId = mapGetDirIdx(ANDROSS_MAP_SHRINE);
            lockLevel(objId, 1);
            warpToMap(0x4e, 0);
            state->fadeAlpha = lbl_803E74D4;
            state->actionState = 0x1f;
        }
        break;
    case 0x1f:
        break;
    }
    camActionParam = lbl_803E7584 + state->camOffsetAccum;
    (*gCameraInterface)->releaseAction(&camActionParam, 4);
    boss->anim.velocityX = state->springStiffness *
                                             (state->targetPosX - boss->anim.localPosX) +
                                         boss->anim.velocityX;
    boss->anim.velocityY = state->springStiffness *
                                             (state->targetPosY - boss->anim.localPosY) +
                                         boss->anim.velocityY;
    boss->anim.velocityZ = state->springStiffness *
                                             (state->targetPosZ - boss->anim.localPosZ) +
                                         boss->anim.velocityZ;
    boss->anim.velocityX = boss->anim.velocityX * state->springDamping;
    boss->anim.velocityY = boss->anim.velocityY * state->springDamping;
    boss->anim.velocityZ = boss->anim.velocityZ * state->springDamping;
    boss->anim.localPosX = boss->anim.localPosX + boss->anim.velocityX;
    boss->anim.localPosY = boss->anim.localPosY + boss->anim.velocityY;
    boss->anim.localPosZ = boss->anim.localPosZ + boss->anim.velocityZ;
    if (lbl_803E74D4 == state->velZ)
    {
        if (state->arwingFlightActive != 0)
        {
            fn_8023A6A4(state, lbl_803DC4B4, lbl_803DC4B8, lbl_803E74D4);
        }
        else
        {
            state->velZ =
                lbl_803DC4B0 * (state->savedPosZ - state->arwingObj->anim.localPosZ);
        }
    }
    if (state->arwingObj->pendingParentObj == NULL)
    {
        velAdd = *(SunVec3*)&state->velX;
        arwarwing_addVelocity((int)state->arwingObj, (int)&velAdd);
    }
    sval = state->targetRotX - (u16)boss->anim.rotX;
    if (0x8000 < sval)
    {
        sval = sval - 0xffff;
    }
    if (sval < -0x8000)
    {
        sval = sval + 0xffff;
    }
    state->rotXSpeed =
        (short)(state->rotXSpeed +
                (((int)sval / lbl_803DC430 - (int)state->rotXSpeed) / lbl_803DC434));
    state->rotYSpeed =
        (short)(state->rotYSpeed +
                ((-(int)boss->anim.rotY / lbl_803DC430 - (int)state->rotYSpeed) /
                 lbl_803DC434));
    boss->anim.rotX += state->rotXSpeed;
    boss->anim.rotY += state->rotYSpeed;
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->animSpeed, timeDelta, 0);
    fn_8023A3E4(obj, (int)state);
    fn_8023A87C(boss, (int)state);
    if (state->spawnedObj != NULL)
    {
        state->spawnedObj->anim.localPosZ -= lbl_803E74D8;
        state->spawnedObjLifetime -= framesThisStep;
        if (state->spawnedObjLifetime < 0)
        {
            Obj_FreeObject((int)state->spawnedObj);
            state->spawnedObjLifetime = 0;
            state->spawnedObj = NULL;
        }
    }
    if (state->fightPhase < 6)
    {
        searchDist0 = lbl_803E7490;
        aimTarget = (GameObject*)ObjList_FindNearestObjectByDefNo(boss, 0x7e5, &searchDist0);
        if (aimTarget != NULL)
        {
            if (aimTarget->pendingParentObj != NULL)
            {
                aimTarget = (GameObject*)aimTarget->pendingParentObj;
            }
            if ((aimTarget->anim.classId != 0x10) ||
                (found = animatedObjGetSeqId((int)aimTarget->extra), found != 0x598))
            {
                aimTarget->anim.placement->posX = boss->anim.localPosX;
                aimTarget->anim.placement->posY = boss->anim.localPosY;
                aimTarget->anim.placement->posZ = boss->anim.localPosZ;
            }
        }
        searchDist1 = lbl_803E7490;
        aimTarget = (GameObject*)ObjList_FindNearestObjectByDefNo(boss, 0x1e, &searchDist1);
        if (aimTarget != NULL)
        {
            if (aimTarget->pendingParentObj != NULL)
            {
                aimTarget = (GameObject*)aimTarget->pendingParentObj;
            }
            if ((aimTarget->anim.classId != 0x10) ||
                (found = animatedObjGetSeqId((int)aimTarget->extra), found != 0x598))
            {
                aimTarget->anim.placement->posX = boss->anim.localPosX;
                aimTarget->anim.placement->posY = boss->anim.localPosY;
                aimTarget->anim.placement->posZ = boss->anim.localPosZ;
            }
        }
        searchDist2 = lbl_803E7490;
        aimTarget = (GameObject*)ObjList_FindNearestObjectByDefNo(boss, 0x76f, &searchDist2);
        if (aimTarget != NULL)
        {
            if (aimTarget->pendingParentObj != NULL)
            {
                aimTarget = (GameObject*)aimTarget->pendingParentObj;
            }
            if ((aimTarget->anim.classId != 0x10) ||
                (found = animatedObjGetSeqId((int)aimTarget->extra), found != 0x598))
            {
                aimTarget->anim.placement->posX = boss->anim.localPosX;
                aimTarget->anim.placement->posY = boss->anim.localPosY;
                aimTarget->anim.placement->posZ = boss->anim.localPosZ;
            }
        }
        searchDist3 = lbl_803E7490;
        aimTarget = (GameObject*)ObjList_FindNearestObjectByDefNo(boss, 0x814, &searchDist3);
        if (aimTarget != NULL)
        {
            if (aimTarget->pendingParentObj != NULL)
            {
                aimTarget = (GameObject*)aimTarget->pendingParentObj;
            }
            if ((aimTarget->anim.classId != 0x10) ||
                (found = animatedObjGetSeqId((int)aimTarget->extra), found != 0x598))
            {
                aimTarget->anim.placement->posX = boss->anim.localPosX;
                aimTarget->anim.placement->posY = boss->anim.localPosY;
                aimTarget->anim.placement->posZ = boss->anim.localPosZ;
            }
        }
        searchDist = lbl_803E7490;
        aimTarget = (GameObject*)ObjList_FindNearestObjectByDefNo(boss, 0x6cf, &searchDist);
        if (aimTarget != NULL)
        {
            if (aimTarget->pendingParentObj != NULL)
            {
                aimTarget = (GameObject*)aimTarget->pendingParentObj;
            }
            if ((aimTarget->anim.classId != 0x10) ||
                (found = animatedObjGetSeqId((int)aimTarget->extra), found != 0x598))
            {
                aimTarget->anim.placement->posX = boss->anim.localPosX;
                aimTarget->anim.placement->posY = boss->anim.localPosY;
                aimTarget->anim.placement->posZ = boss->anim.localPosZ;
            }
        }
    }
    return;
}

int gAndrossSpawnObjectIds[] = {
    0x0004AA57,
    0x0004AA66,
    0x0004AA96,
    0x0004AA97,
};
