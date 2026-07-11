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

extern f32 gAndrossMoveAnimSpeeds[23];
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
    int* state;
    int work;
    u8 stateChanged;
    u8 flag;
    u8 moveChanged;
    int ref;
    int durationBeforeStep;
    GameObject* objAlias;
    u32 val;
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
    f32 fc;
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
    objAlias = (GameObject*)obj;
    state = ((GameObject*)obj)->extra;
    flag = 0;
    stateChanged = 0;
    moveChanged = 0;
    if (((AndrossState*)state)->startupDelay != 0)
    {
        ((AndrossState*)state)->startupDelay -= 1;
        return;
    }
    if (*(void**)&((AndrossState*)state)->handObjA == NULL)
    {
        found = ObjList_FindObjectById(0x47b78);
        ((AndrossState*)state)->handObjA = (GameObject*)found;
    }
    if (*(void**)&((AndrossState*)state)->handObjB == NULL)
    {
        found = ObjList_FindObjectById(0x47b6a);
        ((AndrossState*)state)->handObjB = (GameObject*)found;
    }
    if (*(void**)&((AndrossState*)state)->lightAnchorObj == NULL)
    {
        found = ObjList_FindObjectById(0x47dd9);
        ((AndrossState*)state)->lightAnchorObj = (GameObject*)found;
    }
    if (*(void**)state == NULL)
    {
        found = getArwing();
        *state = found;
        if (*(void**)state != NULL)
        {
            ((AndrossState*)state)->savedPosZ = ((GameObject*)*state)->anim.localPosZ;
            arwarwing_setFlightHalfWidth(*state, gAndrossFlightHalfWidth);
        }
        else
        {
            return;
        }
    }
    /* Update each linked spawn object from its cached relative position. */
    for (work = 0; (u8)work < 4; work++)
    {
        val = work & 0xff;
        found = val * 4 + 0x18;
        if (*(void**)((int)state + found) == NULL)
        {
            *(int*)((int)state + found) = ObjList_FindObjectById(gAndrossSpawnObjectIds[val]);
            if (*(void**)((int)state + found) != NULL)
            {
                ((AndrossState*)state)->spawnDelta[val].x =
                    *(float*)(*(int*)((int)state + found) + 0xc) - ((GameObject*)obj)->anim.localPosX;
                ((AndrossState*)state)->spawnDelta[val].y =
                    *(float*)(*(int*)((int)state + found) + 0x10) - ((GameObject*)obj)->anim.localPosY;
                ((AndrossState*)state)->spawnDelta[val].z =
                    *(float*)(*(int*)((int)state + found) + 0x14) - ((GameObject*)obj)->anim.localPosZ;
            }
        }
        else
        {
            *(float*)(*(int*)((int)state + found) + 0xc) =
                ((GameObject*)obj)->anim.localPosX + ((AndrossState*)state)->spawnDelta[val].x;
            *(float*)(*(int*)((int)state + found) + 0x10) =
                ((GameObject*)obj)->anim.localPosY + ((AndrossState*)state)->spawnDelta[val].y;
            *(float*)(*(int*)((int)state + found) + 0x14) =
                ((GameObject*)obj)->anim.localPosZ + ((AndrossState*)state)->spawnDelta[val].z;
        }
    }
    found = ((AndrossState*)state)->fightPhase;
    if (found != ((AndrossState*)state)->prevFightPhase)
    {
        stateChanged = 1;
    }
    ((AndrossState*)state)->prevFightPhase = found;
    fval = lbl_803E74D4;
    ((AndrossState*)state)->velX = lbl_803E74D4;
    ((AndrossState*)state)->velY = fval;
    ((AndrossState*)state)->velZ = fval;
    if ((-0x4000 < ((AndrossState*)state)->targetRotX) && (((GameObject*)obj)->anim.rotX < 0x4000))
    {
        flag = 1;
    }
    ObjPath_GetPointWorldPosition(obj, flag, (f32*)(state + 0x30), (f32*)(state + 0x31), (f32*)(state + 0x32), 0);
    if (flag == 1)
    {
        fa = ((AndrossState*)state)->cachedPosY;
        fval = gAndrossPathPosOffset;
        ((AndrossState*)state)->cachedPosY = fa + fval;
        ((AndrossState*)state)->cachedPosZ += fval;
    }
    switch (((AndrossState*)state)->fightPhase)
    {
    case 1:
        if (stateChanged)
        {
            if (((AndrossState*)state)->handsInitialized != 0)
            {
                ((AndrossState*)state)->handsInitialized = 0;
            }
            else
            {
                androsshand_setState((GameObject*)(((AndrossState*)state)->handObjA), 2, 1);
                androsshand_setState((GameObject*)(((AndrossState*)state)->handObjB), 2, 1);
            }
            ((AndrossState*)state)->hitsRemaining0 = 10;
            ((AndrossState*)state)->hitsRemaining1 = 10;
            ((AndrossState*)state)->hitsRemaining2 = 10;
        }
        if (((AndrossState*)state)->actionPending != 0)
        {
            switch (((AndrossState*)state)->actionState)
            {
            default:
            case 3:
            case 0x17:
                ((AndrossState*)state)->actionState = 0;
                break;
            case 0:
                ((AndrossState*)state)->actionState = 1;
                break;
            case 0x16:
                if (*(u8*)(state + 0x2e) != 0)
                {
                    ((AndrossState*)state)->actionState = 0x17;
                }
                else
                {
                    ((AndrossState*)state)->actionState = 0;
                }
                break;
            }
            ((AndrossState*)state)->actionPending = 0;
        }
        break;
    case 2:
        if ((stateChanged) && (((AndrossState*)state)->signalFlags &= ~0x6,
                               ((AndrossState*)state)->actionState == 0x16))
        {
            androsshand_setState((GameObject*)(((AndrossState*)state)->handObjA), 1, 1);
            androsshand_setState((GameObject*)(((AndrossState*)state)->handObjB), 1, 1);
        }
        if (((AndrossState*)state)->actionPending != 0)
        {
            switch (((AndrossState*)state)->actionState)
            {
            default:
            case 5:
            case 0x16:
                ((AndrossState*)state)->actionState = 6;
                break;
            case 6:
                ((AndrossState*)state)->actionState = 7;
                break;
            case 7:
                ((AndrossState*)state)->actionState = 10;
                break;
            case 10:
                ((AndrossState*)state)->actionState = 0x12;
                break;
            case 0x14:
                ((AndrossState*)state)->actionState = 0xb;
                break;
            case 0x11:
                ((AndrossState*)state)->actionState = 0x16;
                ((AndrossState*)state)->targetRotX = 0x8000;
                ((AndrossState*)state)->fightPhase--;
            }
            ((AndrossState*)state)->actionPending = 0;
        }
        break;
    case 3:
        if (stateChanged)
        {
            ((AndrossState*)state)->hitsRemaining0 = 0xf;
            ((AndrossState*)state)->hitsRemaining1 = 0xf;
            ((AndrossState*)state)->hitsRemaining2 = 0xf;
            ((AndrossState*)state)->actionState = 0;
            ((AndrossState*)state)->attackCycleCount = 0;
        }
        if (((AndrossState*)state)->actionPending != 0)
        {
            switch (((AndrossState*)state)->actionState)
            {
            default:
            case 0:
                ((AndrossState*)state)->actionState = 1;
                break;
            case 3:
                ((AndrossState*)state)->actionState = 4;
                break;
            case 4:
                ((AndrossState*)state)->attackCycleCount++;
                if (((AndrossState*)state)->attackCycleCount > 3)
                {
                    ((AndrossState*)state)->fightPhase--;
                    ((AndrossState*)state)->actionState = 0x16;
                    ((AndrossState*)state)->targetRotX = 0;
                }
                else
                {
                    ((AndrossState*)state)->actionState = 0;
                }
                break;
            }
            ((AndrossState*)state)->actionPending = 0;
        }
        break;
    case 4:
        if (((AndrossState*)state)->actionPending != 0)
        {
            switch (((AndrossState*)state)->actionState)
            {
            default:
            case 5:
            case 0x16:
                ((AndrossState*)state)->actionState = 6;
                break;
            case 6:
                ((AndrossState*)state)->actionState = 7;
                break;
            case 7:
                ((AndrossState*)state)->actionState = 10;
                break;
            case 10:
                ((AndrossState*)state)->actionState = 0x12;
                break;
            case 0x14:
                ((AndrossState*)state)->actionState = 0xb;
                break;
            case 0xf:
                ((AndrossState*)state)->actionState = 9;
                break;
            case 9:
                ((AndrossState*)state)->actionState = 8;
                break;
            case 0x11:
                ((AndrossState*)state)->actionState = 0x18;
            }
            ((AndrossState*)state)->actionPending = 0;
        }
        break;
    case 5:
        if (stateChanged)
        {
            ((AndrossState*)state)->actionState = 0xd;
            ((AndrossState*)state)->actionToggle = 0;
        }
        if (((AndrossState*)state)->actionPending != 0)
        {
            switch (((AndrossState*)state)->actionState)
            {
            default:
            case 0x1b:
                ((AndrossState*)state)->unkB1[0] = 3;
            case 0xf:
                ((AndrossState*)state)->actionState = 0x12;
                ((AndrossState*)state)->actionToggle = 0;
                break;
            case 0x14:
                switch (((AndrossState*)state)->actionToggle)
                {
                case 0:
                    ((AndrossState*)state)->actionState = 0x15;
                    break;
                case 1:
                    ((AndrossState*)state)->actionState = 0xb;
                    break;
                }
                ((AndrossState*)state)->actionToggle ^= 1;
                break;
            case 0x15:
                ((AndrossState*)state)->actionState = 0x12;
                break;
            case 0x11:
                ((AndrossState*)state)->actionState = 0x18;
                break;
            case 0x19:
                ((AndrossState*)state)->fightPhase = 6;
                break;
            case 0x1a:
                ((AndrossState*)state)->actionState = 0x1b;
            }
            ((AndrossState*)state)->actionPending = 0;
        }
        break;
    case 6:
        if (stateChanged)
        {
            ((AndrossState*)state)->actionState = 0x1c;
            ((AndrossState*)state)->actionToggle = 0;
        }
        break;
    }
    flag = moveChanged;
    found = ((AndrossState*)state)->actionState;
    if (found != ((AndrossState*)state)->prevActionState)
    {
        flag = 1;
    }
    ((AndrossState*)state)->prevActionState = found;
    switch (((AndrossState*)state)->actionState)
    {
    case 0:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[0];
            if (((AndrossState*)state)->fightPhase == 1)
            {
                ((AndrossState*)state)->durationTimer = lbl_803E74E4;
            }
            else
            {
                ((AndrossState*)state)->durationTimer = lbl_803E74E8;
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        ((AndrossState*)state)->durationTimer -= timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        val = ((AndrossState*)state)->hitsRemaining0;
        val = val + ((AndrossState*)state)->hitsRemaining1;
        val = val + ((AndrossState*)state)->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            ((AndrossState*)state)->fightPhase++;
            ((AndrossState*)state)->actionState = 5;
            ((AndrossState*)state)->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 1:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0xc, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[12];
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionState = 2;
            ((AndrossState*)state)->actionPending = 0;
        }
        val = ((AndrossState*)state)->hitsRemaining0;
        val = val + ((AndrossState*)state)->hitsRemaining1;
        val = val + ((AndrossState*)state)->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            ((AndrossState*)state)->fightPhase++;
            ((AndrossState*)state)->actionState = 5;
            ((AndrossState*)state)->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 2:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0xe, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[14];
            ((AndrossState*)state)->durationTimer = lbl_803E74F0;
            ((AndrossState*)state)->actionTimer = 0xffff;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_roar1);
        ((AndrossState*)state)->actionTimer -= framesThisStep;
        if (((AndrossState*)state)->actionTimer < 0)
        {
            fn_8023A268(obj, (int)state, 0);
            ((AndrossState*)state)->actionTimer = lbl_803DC43C;
        }
        ((AndrossState*)state)->durationTimer -= timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            ((AndrossState*)state)->actionState = 3;
            ((AndrossState*)state)->actionPending = 0;
        }
        val = ((AndrossState*)state)->hitsRemaining0;
        val = val + ((AndrossState*)state)->hitsRemaining1;
        val = val + ((AndrossState*)state)->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            ((AndrossState*)state)->fightPhase++;
            ((AndrossState*)state)->actionState = 5;
            ((AndrossState*)state)->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 3:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0xd, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[13];
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 4:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[0];
            mainSetBits(0xd, 1);
            ((AndrossState*)state)->durationTimer = lbl_803E7504;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        ((AndrossState*)state)->durationTimer -= timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            ((AndrossState*)state)->actionPending = 1;
            mainSetBits(0xd, 0);
        }
        val = ((AndrossState*)state)->hitsRemaining0;
        val = val + ((AndrossState*)state)->hitsRemaining1;
        val = val + ((AndrossState*)state)->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            ((AndrossState*)state)->fightPhase++;
            ((AndrossState*)state)->actionState = 5;
            ((AndrossState*)state)->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 0x15:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[0];
            mainSetBits(0xd, 1);
            ((AndrossState*)state)->durationTimer = lbl_803E7504;
        }
        for (ref = 0; (u8)ref < 6; ref++)
        {
            if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
            {
                ((AndrossState*)state)->timer = 0x3c;
                goto hit_cue_ready_15;
            }
        }
        ((AndrossState*)state)->timer -= framesThisStep;
        if (((AndrossState*)state)->timer <= 0)
        {
            ref = randomGetRange(0, 5);
            mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
            ((AndrossState*)state)->timer = 0x3c;
        }
    hit_cue_ready_15:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        ((AndrossState*)state)->durationTimer -= timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            ((AndrossState*)state)->actionPending = 1;
            mainSetBits(0xd, 0);
        }
        break;
    case 6:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[0];
            androsshand_setState((GameObject*)(((AndrossState*)state)->handObjB), 4, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E7508) ? lbl_803E7508 : ((fb > lbl_803E750C) ? lbl_803E750C : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        flag = 0;
        found = *(int*)&((GameObject*)obj)->extra;
        signals = *(u8*)(found + 0xad);
        if ((signals & 1) != 0)
        {
            *(u8*)(found + 0xad) = signals & ~1;
            flag = 1;
        }
        if (flag != 0)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 7:
        if (flag)
        {
            androsshand_setState((GameObject*)(((AndrossState*)state)->handObjA), 4, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E7508) ? lbl_803E7508 : ((fb > lbl_803E750C) ? lbl_803E750C : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        flag = 0;
        found = *(int*)&((GameObject*)obj)->extra;
        signals = *(u8*)(found + 0xad);
        if ((signals & 1) != 0)
        {
            *(u8*)(found + 0xad) = signals & ~1;
            flag = 1;
        }
        if (flag != 0)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 9:
        if (flag)
        {
            androsshand_setState((GameObject*)(((AndrossState*)state)->handObjA), 6, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        flag = 0;
        found = *(int*)&((GameObject*)obj)->extra;
        signals = *(u8*)(found + 0xad);
        if ((signals & 1) != 0)
        {
            *(u8*)(found + 0xad) = signals & ~1;
            flag = 1;
        }
        if (flag != 0)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 8:
        if (flag)
        {
            androsshand_setState((GameObject*)(((AndrossState*)state)->handObjB), 6, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        flag = 0;
        found = *(int*)&((GameObject*)obj)->extra;
        signals = *(u8*)(found + 0xad);
        if ((signals & 1) != 0)
        {
            *(u8*)(found + 0xad) = signals & ~1;
            flag = 1;
        }
        if (flag != 0)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 10:
        if ((((AndrossState*)state)->signalFlags & 6) == 6)
        {
            ((AndrossState*)state)->fightPhase++;
            if (((AndrossState*)state)->fightPhase < 5)
            {
                Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
                ((AndrossState*)state)->actionState = 0x16;
                ((AndrossState*)state)->targetRotX = 0x8000;
            }
        }
        else
        {
            gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
            gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
            fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
            fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
            fc = (fb < lbl_803E7508) ? lbl_803E7508 : ((fb > lbl_803E750C) ? lbl_803E750C : fb);
            fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
            fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
            ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa + (float)(((AndrossState*)state)->homePosX + fc));
            fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
            ((AndrossState*)state)->targetPosY =
                (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
            ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
            if (flag)
            {
                androsshand_setState((GameObject*)(((AndrossState*)state)->handObjA), 5, 0);
                androsshand_setState((GameObject*)(((AndrossState*)state)->handObjB), 5, 0);
            }
            flag = 0;
            found = *(int*)&((GameObject*)obj)->extra;
            signals = *(u8*)(found + 0xad);
            if ((signals & 1) != 0)
            {
                *(u8*)(found + 0xad) = signals & ~1;
                flag = 1;
            }
            if (flag != 0)
            {
                ((AndrossState*)state)->actionPending = 1;
            }
        }
        break;
    case 0xb:
    case 0xd:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[1];
            if (((AndrossState*)state)->fightPhase < 5)
            {
                androsshand_setState((GameObject*)(((AndrossState*)state)->handObjA), 0, 0);
                androsshand_setState((GameObject*)(((AndrossState*)state)->handObjB), 0, 0);
            }
            else
            {
                androsshand_setState((GameObject*)(((AndrossState*)state)->handObjA), 9, 1);
                androsshand_setState((GameObject*)(((AndrossState*)state)->handObjB), 9, 1);
                ((AndrossState*)state)->signalFlags |= 6;
            }
        }
        if ((((AndrossState*)state)->fightPhase == 5) && (((AndrossState*)state)->actionState == 0xb))
        {
            for (ref = 0; (u8)ref < 6; ref++)
            {
                if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    ((AndrossState*)state)->timer = 0x3c;
                    goto hit_cue_ready_b_or_d;
                }
            }
            ((AndrossState*)state)->timer -= framesThisStep;
            if (((AndrossState*)state)->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                ((AndrossState*)state)->timer = 0x3c;
            }
        }
    hit_cue_ready_b_or_d:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E7510) ? lbl_803E7510 : ((fb > gAndrossSwayAmplitudeY) ? gAndrossSwayAmplitudeY : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeY * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (lbl_803E7514 * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            switch (((AndrossState*)state)->actionState)
            {
            default:
            case 0xb:
                ((AndrossState*)state)->actionState = 0xc;
                break;
            case 0xd:
                ((AndrossState*)state)->actionState = 0xe;
                break;
            }
        }
        fval = lbl_803E74B8 * ((GameObject*)obj)->anim.currentMoveProgress;
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
        turnOnDistortionFilter((f32*)(state + 0x30), fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        break;
    case 0xe:
        fval = lbl_803E74B8 * ((GameObject*)obj)->anim.currentMoveProgress + lbl_803E74B8;
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
        turnOnDistortionFilter((f32*)(state + 0x30), fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[2];
            ((AndrossState*)state)->unkB1[0] = 0;
            mainSetBits(0x10, 0);
            ((AndrossState*)state)->actionTimer = lbl_803DC44C;
            ((AndrossState*)state)->durationTimer = lbl_803E74D4;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7508) ? lbl_803E7508 : ((fa > lbl_803E750C) ? lbl_803E750C : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeY * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (lbl_803E7514 * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        fn_8023A6A4((AndrossState*)state, lbl_803DC440, lbl_803DC444, lbl_803DC448);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_missileloop);
        if ((((AndrossState*)state)->actionTimer != 0) &&
            (((AndrossState*)state)->actionTimer -= framesThisStep, ((AndrossState*)state)->actionTimer <= 0))
        {
            ((AndrossState*)state)->actionTimer = 0;
            mainSetBits(0xf, 1);
        }
        ((AndrossState*)state)->durationTimer -= timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            fn_80239FCC(obj, (int)state);
            ((AndrossState*)state)->durationTimer += (f32)(lbl_803DC450);
        }
        fn_80239EAC(obj, (int)state);
        if ((u32)mainGetBit(0x10) != 0)
        {
            mainSetBits(0x10, 0);
            ((AndrossState*)state)->actionState = 0x1a;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossDistortPhaseWrap)
            {
                gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
            }
            turnOnDistortionFilter((f32*)(state + 0x30), lbl_803E74BC, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    case 0xc:
        fval = lbl_803E74B8 * ((GameObject*)obj)->anim.currentMoveProgress + lbl_803E74B8;
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
        turnOnDistortionFilter((f32*)(state + 0x30), fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[2];
            if (((AndrossState*)state)->fightPhase < 5)
            {
                ((AndrossState*)state)->unkB1[0] = 1;
            }
            ((AndrossState*)state)->actionTimer = lbl_803DC460;
            ((AndrossState*)state)->durationTimer = lbl_803E74D4;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_missileloop);
        if (((AndrossState*)state)->fightPhase == 5)
        {
            for (ref = 0; (u8)ref < 6; ref++)
            {
                if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    ((AndrossState*)state)->timer = 0x3c;
                    goto hit_cue_ready_c;
                }
            }
            ((AndrossState*)state)->timer -= framesThisStep;
            if (((AndrossState*)state)->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                ((AndrossState*)state)->timer = 0x3c;
            }
        }
    hit_cue_ready_c:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74F4) ? lbl_803E74F4 : ((fb > lbl_803E74F8) ? lbl_803E74F8 : fb);
        fb = (fa < lbl_803E7510) ? lbl_803E7510 : ((fa > gAndrossSwayAmplitudeY) ? gAndrossSwayAmplitudeY : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeY * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (lbl_803E7514 * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        bval = fn_8023A6A4((AndrossState*)state, lbl_803DC454, lbl_803DC458, lbl_803DC45C);
        if (bval != 0)
        {
            ((AndrossState*)state)->actionState = 0xf;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossDistortPhaseWrap)
            {
                gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
            }
            turnOnDistortionFilter((f32*)(state + 0x30), lbl_803E74BC, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        ((AndrossState*)state)->durationTimer -= timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            fn_80239FCC(obj, (int)state);
            ((AndrossState*)state)->durationTimer += (f32)(lbl_803DC464);
        }
        fn_80239EAC(obj, (int)state);
        if (((AndrossState*)state)->hitReactionFlag != 0)
        {
            if (((AndrossState*)state)->fightPhase == 5)
            {
                ((AndrossState*)state)->actionState = 0x19;
            }
            else
            {
                ((AndrossState*)state)->actionState = 0xf;
            }
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossDistortPhaseWrap)
            {
                gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
            }
            turnOnDistortionFilter((f32*)(state + 0x30), lbl_803E74BC, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        else
        {
            if (((GameObject*)*state)->anim.localPosZ > ((AndrossState*)state)->cachedPosZ)
            {
                ((AndrossState*)state)->actionState = 0x10;
                *(u8*)(state + 0x2e) = 1;
                ((GameObject*)*state)->anim.localPosZ = ((AndrossState*)state)->cachedPosZ;
                ((AndrossState*)state)->velZ = lbl_803E74D4;
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
                fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
                gAndrossDistortPhase = fval;
                if (fval > gAndrossDistortPhaseWrap)
                {
                    gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
                }
                turnOnDistortionFilter((f32*)(state + 0x30), lbl_803E74BC, &gAndrossDistortFilterParam,
                                       gAndrossDistortPhase);
                Rcp_DisableDistortionFilter();
                break;
            }
        }
        ((AndrossState*)state)->actionTimer -= framesThisStep;
        if (((AndrossState*)state)->actionTimer < 0)
        {
            ((AndrossState*)state)->actionState = 0xf;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossDistortPhaseWrap)
            {
                gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
            }
            turnOnDistortionFilter((f32*)(state + 0x30), lbl_803E74BC, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    case 0xf:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x10, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[16];
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E7500) ? lbl_803E7500 : ((fb > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x10:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x10, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_803E7518;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        zero = lbl_803E74D4;
        fc = (fb < zero) ? zero : ((fb > zero) ? zero : fb);
        zero = *(f32*)&lbl_803E74D4;
        fb = (fa < zero) ? zero : ((fa > zero) ? zero : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74D4 * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (lbl_803E74D4 * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        fc = ((AndrossState*)state)->cachedPosX - *(float*)&((AndrossState*)*state)->lightAnchorObj;
        velCalc3.x = fc * lbl_803DC468;
        fc = ((AndrossState*)state)->cachedPosY - *(float*)&((AndrossState*)*state)->effectHandle;
        velCalc3.y = fc * lbl_803DC468;
        fc = ((AndrossState*)state)->cachedPosZ - *(float*)&((AndrossState*)*state)->spawnedObj;
        velCalc3.z = fc * lbl_803DC468;
        velArg3 = velCalc3;
        arwarwing_setVelocity(*state, (int)&velArg3);
        fval = (lbl_803E74EC > -(lbl_803E74B0 * timeDelta - ((AndrossState*)state)->camOffsetAccum))
                   ? lbl_803E74EC
                   : -(lbl_803E74B0 * timeDelta - ((AndrossState*)state)->camOffsetAccum);
        ((AndrossState*)state)->camOffsetAccum = fval;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            *(s16*)(*state + 6) = *(s16*)(*state + 6) | 0x4000;
            ((AndrossState*)state)->actionState = 0x11;
        }
        break;
    case 0x11:
        if (flag)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_and_falcoflyby);
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x15, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[21];
            arwarwing_addHealth(*state, 0xfffffffc);
        }
        fval = (lbl_803E74EC > -(lbl_803E74B0 * timeDelta - ((AndrossState*)state)->camOffsetAccum))
                   ? lbl_803E74EC
                   : -(lbl_803E74B0 * timeDelta - ((AndrossState*)state)->camOffsetAccum);
        ((AndrossState*)state)->camOffsetAccum = fval;
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        zero = lbl_803E74D4;
        fc = (fb < zero) ? zero : ((fb > zero) ? zero : fb);
        zero = *(f32*)&lbl_803E74D4;
        fb = (fa < zero) ? zero : ((fa > zero) ? zero : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74D4 * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (lbl_803E74D4 * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x12:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x12, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[18];
            androsshand_setState((GameObject*)(((AndrossState*)state)->handObjA), 0, 0);
            androsshand_setState((GameObject*)(((AndrossState*)state)->handObjB), 0, 0);
            if ((((AndrossState*)state)->fightPhase == 5) && (((AndrossState*)state)->actionToggle != 0))
            {
                mainSetBits(0xe, 1);
            }
        }
        ((AndrossState*)state)->fadeAlpha -= gAndrossFadeAlphaStep;
        fval = (lbl_803E74D4 > ((AndrossState*)state)->fadeAlpha) ? lbl_803E74D4 : ((AndrossState*)state)->fadeAlpha;
        ((AndrossState*)state)->fadeAlpha = fval;
        {
            f32 alpha = ((AndrossState*)state)->fadeAlpha;

            ref = *(int*)Obj_GetActiveModel(obj);
            work = 0;
            alpha = gAndrossAlpha255 * alpha;
            for (; work < (int)(u32) * (u8*)(ref + 0xf8); work++)
            {
                found = ObjModel_GetRenderOp(ref, work);
                ((AndrossState*)found)->alpha = alpha;
            }
        }
        if ((((AndrossState*)state)->fightPhase == 5) && (((AndrossState*)state)->actionToggle == 0))
        {
            for (ref = 0; (u8)ref < 6; ref++)
            {
                if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    ((AndrossState*)state)->timer = 0x3c;
                    goto hit_cue_ready_12;
                }
            }
            ((AndrossState*)state)->timer -= framesThisStep;
            if (((AndrossState*)state)->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                ((AndrossState*)state)->timer = 0x3c;
            }
        }
    hit_cue_ready_12:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionState = 0x13;
        }
        break;
    case 0x13:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[19];
            if (((AndrossState*)state)->fightPhase == 5)
            {
                ((AndrossState*)state)->durationTimer = lbl_803E74A8;
            }
            else
            {
                ((AndrossState*)state)->durationTimer = lbl_803E74F0;
            }
            ((AndrossState*)state)->actionTimer = 0xffff;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_spitout);
        if ((((AndrossState*)state)->fightPhase == 5) && (((AndrossState*)state)->actionToggle == 0))
        {
            for (ref = 0; (u8)ref < 6; ref++)
            {
                if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    ((AndrossState*)state)->timer = 0x3c;
                    goto hit_cue_ready_13;
                }
            }
            ((AndrossState*)state)->timer -= framesThisStep;
            if (((AndrossState*)state)->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                ((AndrossState*)state)->timer = 0x3c;
            }
        }
    hit_cue_ready_13:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E7520) ? lbl_803E7520 : ((fb > lbl_803E74A8) ? lbl_803E74A8 : fb);
        fb = (fa < lbl_803E7524) ? lbl_803E7524 : ((fa > lbl_803E7528) ? lbl_803E7528 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        ((AndrossState*)state)->actionTimer -= framesThisStep;
        durationBeforeStep = (int)((AndrossState*)state)->durationTimer;
        ((AndrossState*)state)->durationTimer -= framesThisStep;
        if (((AndrossState*)state)->fightPhase == 5)
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
            if (((((void*)((AndrossState*)state)->spawnedObj == NULL) &&
                  (((AndrossState*)state)->actionTimer <= delayPair[(u8)ref])) &&
                 ((short)durationBeforeStep > delayPair[(u8)ref])) &&
                (Obj_IsLoadingLocked() != 0))
            {
                found = Obj_AllocObjectSetup(0x24, ANDROSS_CHILD_OBJ_SPAWNED);
                *(f32*)&((AndrossState*)found)->handObjB = ((AndrossState*)state)->cachedPosX;
                *(f32*)&((AndrossState*)found)->lightAnchorObj = ((AndrossState*)state)->cachedPosY;
                *(f32*)&((AndrossState*)found)->effectHandle = ((AndrossState*)state)->cachedPosZ;
                *(u8*)(found + 4) = 1;
                *(u8*)(found + 5) = 1;
                ((AndrossState*)found)->unk20 = 0xffff;
                found = ((int (*)(int, int))loadObjectAtObject)(obj, found);
                ((AndrossState*)state)->spawnedObj = (GameObject*)found;
                if ((void*)((AndrossState*)state)->spawnedObj != NULL)
                {
                    ((GameObject*)((AndrossState*)state)->spawnedObj)->anim.alpha = 0xff;
                    *((u8*)((AndrossState*)state)->spawnedObj + 0x37) = 0xff;
                    ((AndrossState*)state)->spawnedObjLifetime = lbl_803DC4EC;
                }
            }
        }
        if (((AndrossState*)state)->actionTimer < 0)
        {
            fn_8023A168(obj, (int)state);
            ((AndrossState*)state)->actionTimer = lbl_803DC46C;
        }
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            ((AndrossState*)state)->actionState = 0x14;
        }
        break;
    case 0x14:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x14, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[20];
        }
        if ((((AndrossState*)state)->fightPhase == 5) && (((AndrossState*)state)->actionToggle == 0))
        {
            for (ref = 0; (u8)ref < 6; ref++)
            {
                if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    ((AndrossState*)state)->timer = 0x3c;
                    goto hit_cue_ready_14;
                }
            }
            ((AndrossState*)state)->timer -= framesThisStep;
            if (((AndrossState*)state)->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                ((AndrossState*)state)->timer = 0x3c;
            }
        }
    hit_cue_ready_14:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E752C) ? lbl_803E752C : ((fa > lbl_803E74E8) ? lbl_803E74E8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) / lbl_803E74A4));
        ((AndrossState*)state)->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x19:
    case 0x1a:
        if (flag)
        {
            Sfx_PlayFromObject(obj, SFXTRIG__UNK_832);
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[4];
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x1b:
        if (flag)
        {
            mainSetBits(0x10, 0);
            ((AndrossState*)state)->actionTimer = 0x1e;
            arwarwing_resetFlightState((GameObject*)(*state));
            ((GameObject*)*state)->anim.localPosZ = ((AndrossState*)state)->savedPosZ;
            ((AndrossState*)state)->camOffsetAccum = lbl_803E74D4;
        }
        ((AndrossState*)state)->targetPosX = ((AndrossState*)state)->homePosX;
        ((AndrossState*)state)->targetPosY = ((AndrossState*)state)->homePosY;
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((u32)mainGetBit(0x10) != 0) && (((AndrossState*)state)->actionTimer-- == 0))
        {
            mainSetBits(0x10, 0);
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x1c:
        if (flag)
        {
            androssbrain_setState((GameObject*)(((AndrossState*)state)->lightAnchorObj), 1, 0);
            ObjHits_DisableObject(obj);
            ((AndrossState*)state)->actionTimer = 0x3c;
            ((AndrossState*)state)->durationTimer = lbl_803E74D8;
            ((AndrossState*)state)->targetPosX = ((AndrossState*)state)->homePosX;
            ((AndrossState*)state)->targetPosY = ((AndrossState*)state)->homePosY;
            ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
            fval = lbl_803E74D4;
            ((GameObject*)obj)->anim.velocityX = lbl_803E74D4;
            ((GameObject*)obj)->anim.velocityY = fval;
            ((GameObject*)obj)->anim.velocityZ = fval;
            ((AndrossState*)state)->springStiffness = lbl_803E74C8;
            ((AndrossState*)state)->springDamping = gAndrossSpringDamping;
        }
        ((AndrossState*)state)->fadeAlpha += gAndrossFadeAlphaStep;
        fval = (gAndrossFadeAlphaMax < ((AndrossState*)state)->fadeAlpha) ? gAndrossFadeAlphaMax
                                                                          : ((AndrossState*)state)->fadeAlpha;
        ((AndrossState*)state)->fadeAlpha = fval;
        for (ref = 0; (u8)ref < 6; ref++)
        {
            if ((u32)mainGetBit((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
            {
                ((AndrossState*)state)->timer = 0x3c;
                goto hit_cue_ready_1c;
            }
        }
        ((AndrossState*)state)->timer -= framesThisStep;
        if (((AndrossState*)state)->timer <= 0)
        {
            ref = randomGetRange(0, 5);
            mainSetBits(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
            ((AndrossState*)state)->timer = 0x3c;
        }
    hit_cue_ready_1c:
        ((AndrossState*)state)->actionTimer -= framesThisStep;
        if (((AndrossState*)state)->actionTimer < 0)
        {
            ((AndrossState*)state)->durationTimer -= lbl_803E74DC;
            if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
            {
                ((AndrossState*)state)->actionToggle += 1;
                if (((AndrossState*)state)->actionToggle > 3)
                {
                    ((AndrossState*)state)->fightPhase = 5;
                    ((AndrossState*)state)->prevFightPhase = 5;
                    ((AndrossState*)state)->actionToggle = 0;
                    ((AndrossState*)state)->actionState = 0x12;
                    androssbrain_setState((GameObject*)(((AndrossState*)state)->lightAnchorObj), 0, 0);
                    ObjHits_EnableObject(obj);
                }
                else
                {
                    ((AndrossState*)state)->actionState = 0x1d;
                }
            }
            else
            {
                randVal = randomGetRange(0x14, 0x1e);
                ((AndrossState*)state)->actionTimer = randVal;
                ((AndrossState*)state)->targetPosX =
                    (f32)(int)randomGetRange((int)-gAndrossSpawnRandX, gAndrossSpawnRandX) +
                    ((AndrossState*)state)->homePosX;
                ((AndrossState*)state)->targetPosY =
                    (f32)(int)randomGetRange((int)-gAndrossSpawnRandY, gAndrossSpawnRandY) +
                    ((AndrossState*)state)->homePosY;
                ((AndrossState*)state)->targetPosZ =
                    (f32)(int)randomGetRange((int)-gAndrossSpawnRandZ, gAndrossSpawnRandZ) +
                    ((AndrossState*)state)->homePosZ;
            }
        }
        if ((((AndrossState*)state)->signalFlags & 8) != 0)
        {
            arwingHudSetVisible(2);
            mainSetBits(1, 1);
            mainSetBits(0x4b1, 1);
            ((AndrossState*)state)->actionState = 0x1e;
            unlockLevel(0, 0, 1);
            objId = mapGetDirIdx(ANDROSS_MAP_SHRINE);
            mapUnload(objId, 0x20000000);
            Music_Trigger(MUSICTRIG_Mound_Music, 0);
        }
        {
            f32 alpha = ((AndrossState*)state)->fadeAlpha;

            ref = *(int*)Obj_GetActiveModel(obj);
            work = 0;
            alpha = gAndrossAlpha255 * alpha;
            for (; work < (int)(u32) * (u8*)(ref + 0xf8); work++)
            {
                found = ObjModel_GetRenderOp(ref, work);
                ((AndrossState*)found)->alpha = alpha;
            }
        }
        break;
    case 0x1d:
        if (flag)
        {
            androssbrain_setState((GameObject*)(((AndrossState*)state)->lightAnchorObj), 1, 0);
            ObjHits_DisableObject(obj);
            ((AndrossState*)state)->actionTimer = lbl_803DC484;
            ((AndrossState*)state)->targetPosX = ((GameObject*)*state)->anim.localPosX;
            ((AndrossState*)state)->targetPosY = ((GameObject*)*state)->anim.localPosY + gAndrossSpawnOffsetY;
            ((AndrossState*)state)->targetPosZ = ((GameObject*)*state)->anim.localPosZ + gAndrossSpawnOffsetZ;
            fval = lbl_803E74D4;
            ((GameObject*)obj)->anim.velocityX = lbl_803E74D4;
            ((GameObject*)obj)->anim.velocityY = fval;
            ((GameObject*)obj)->anim.velocityZ = fval;
            Sfx_PlayFromObject((int)objAlias,
                               randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
        }
        ((AndrossState*)state)->actionTimer -= framesThisStep;
        if (((AndrossState*)state)->actionTimer < 0)
        {
            ((AndrossState*)state)->actionState = 0x1c;
        }
        break;
    case 0x16:
        if (flag)
        {
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[0];
        }
        if (*(u8*)(state + 0x2e) != 0)
        {
            fc = ((AndrossState*)state)->cachedPosX - *(float*)&((AndrossState*)*state)->lightAnchorObj;
            velCalc2.x = fc * lbl_803DC488;
            fc = ((AndrossState*)state)->cachedPosY - *(float*)&((AndrossState*)*state)->effectHandle;
            velCalc2.y = fc * lbl_803DC488;
            fc = ((AndrossState*)state)->cachedPosZ - *(float*)&((AndrossState*)*state)->spawnedObj;
            velCalc2.z = fc * lbl_803DC488;
            velArg2 = velCalc2;
            arwarwing_setVelocity(*state, (int)&velArg2);
            fval = (lbl_803E7538 > -(lbl_803E753C * timeDelta - ((AndrossState*)state)->camOffsetAccum))
                       ? lbl_803E7538
                       : -(lbl_803E753C * timeDelta - ((AndrossState*)state)->camOffsetAccum);
            ((AndrossState*)state)->camOffsetAccum = fval;
        }
        sval = ((AndrossState*)state)->targetRotX - (u16)((GameObject*)obj)->anim.rotX;
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
            found = *(int*)((int)((AndrossState*)state)->handObjB + 0xb8);
            bval = *(char*)(*(int*)((int)((AndrossState*)state)->handObjA + 0xb8) + 0x23);
            if ((((bval != 2) && (bval != 1)) && (bval = *(char*)&((AndrossState*)found)->handState, bval != 2)) &&
                (bval != 1))
            {
                ((AndrossState*)state)->actionPending = 1;
            }
        }
        break;
    case 5:
        work = *(int*)((int)((AndrossState*)state)->handObjA + 0xb8);
        ref = *(int*)((int)((AndrossState*)state)->handObjB + 0xb8);
        if (flag)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_drak_roar1);
            found = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x16, lbl_803E74D4, 0);
            *(f32*)(found + 100) = gAndrossMoveAnimSpeeds[22];
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f80 = 0;
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f40 = 0;
        }
        fc = ((GameObject*)obj)->anim.currentMoveProgress;
        if (fc < lbl_803E7540)
        {
            fc = mathSinf(
                ((lbl_803E74A0 * (float)(lbl_803E7548 * (lbl_803E7550 * (fc / lbl_803E7540)))) / lbl_803E74A4));
            ((AndrossState*)state)->targetPosZ = (lbl_803E74A8 * fc + ((AndrossState*)state)->homePosZ);
        }
        else
        {
            fc = mathSinf(((lbl_803E74A0 * (float)(lbl_803E7548 * (lbl_803E7558 * ((fc - lbl_803E7540) / lbl_803E7560) +
                                                                   lbl_803E7550))) /
                           lbl_803E74A4));
            ((AndrossState*)state)->targetPosZ = ((f32)(lbl_803DC48C)*fc + ((AndrossState*)state)->homePosZ);
        }
        if ((((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7568) &&
            ((((AndrossState*)state)->soundEventFlags >> 6 & 1) == 0u))
        {
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f40 = 1;
        }
        if ((((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7570) &&
            (((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f80 == 0))
        {
            Sfx_PlayFromObject(obj, SFXTRIG_and_laugh);
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f80 = 1;
        }
        bval = *(char*)&((AndrossState*)work)->handState;
        if ((((bval != 2) && (bval != 1)) && (bval = *(char*)&((AndrossState*)ref)->handState, bval != 2)) &&
            (bval != 1))
        {
            if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
            {
                ((AndrossState*)state)->actionPending = 1;
            }
            else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7568)
            {
                ((AndrossState*)state)->targetRotX = 0;
                androsshand_setState((GameObject*)(((AndrossState*)state)->handObjA), 1,
                                     (u8)((((AndrossState*)state)->fightPhase == 4) + 1));
                androsshand_setState((GameObject*)(((AndrossState*)state)->handObjB), 1,
                                     (u8)((((AndrossState*)state)->fightPhase == 4) + 1));
                ((AndrossState*)state)->signalFlags &= ~0x6;
            }
        }
        break;
    case 0x17:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 3, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[3];
            ((AndrossState*)state)->soundTimer = lbl_803E74D4;
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f20 = 0;
        }
        ((AndrossState*)state)->soundTimer += timeDelta;
        if ((((AndrossState*)state)->soundTimer > lbl_803E7578) &&
            ((((AndrossState*)state)->soundEventFlags >> 5 & 1) == 0u))
        {
            Sfx_PlayFromObject(obj, SFXTRIG_drak_pain1);
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f20 = 1;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress <= lbl_803DC490)
        {
            ((AndrossState*)state)->cachedPosX = ((GameObject*)obj)->anim.localPosX;
            ((AndrossState*)state)->cachedPosY = ((GameObject*)obj)->anim.localPosY - gAndrossCachedPosOffsetY;
            ((AndrossState*)state)->cachedPosZ = ((GameObject*)obj)->anim.localPosZ - gAndrossCachedPosOffsetZ;
            fc = ((AndrossState*)state)->cachedPosX - *(float*)&((AndrossState*)*state)->lightAnchorObj;
            velCalc1.x = fc * lbl_803DC494;
            fc = ((AndrossState*)state)->cachedPosY - *(float*)&((AndrossState*)*state)->effectHandle;
            velCalc1.y = fc * lbl_803DC494;
            fc = ((AndrossState*)state)->cachedPosZ - *(float*)&((AndrossState*)*state)->spawnedObj;
            velCalc1.z = fc * lbl_803DC494;
            velArg1 = velCalc1;
            arwarwing_setVelocity(*state, (int)&velArg1);
        }
        else
        {
            fc = (((AndrossState*)state)->savedPosZ - ((GameObject*)*state)->anim.localPosZ);
            fval = (lbl_803E74D4 < lbl_803E753C * timeDelta + ((AndrossState*)state)->camOffsetAccum)
                       ? lbl_803E74D4
                       : lbl_803E753C * timeDelta + ((AndrossState*)state)->camOffsetAccum;
            ((AndrossState*)state)->camOffsetAccum = fval;
            *(u8*)(state + 0x2e) = 0;
            *(s16*)(*state + 6) = *(s16*)(*state + 6) & ~0x4000;
            ref = (int)((f32)(s16)arwarwing_getRotY(*state) + fc * lbl_803DC49C);
            arwarwing_setRotY(*state, ref);
            thrustB.x = lbl_803E74D4;
            thrustB.y = lbl_803E74D4;
            thrustB.z = (float)(fc * lbl_803DC498);
            thrustBArg = thrustB;
            arwarwing_setVelocity(*state, (int)&thrustBArg);
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x18:
        if (flag)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = gAndrossMoveAnimSpeeds[17];
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f20 = 0;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress <= lbl_803DC4A0)
        {
            fc = ((AndrossState*)state)->cachedPosX - *(float*)&((AndrossState*)*state)->lightAnchorObj;
            velCalc0.x = fc * lbl_803DC4A4;
            fc = ((AndrossState*)state)->cachedPosY - *(float*)&((AndrossState*)*state)->effectHandle;
            velCalc0.y = fc * lbl_803DC4A4;
            fc = ((AndrossState*)state)->cachedPosZ - *(float*)&((AndrossState*)*state)->spawnedObj;
            velCalc0.z = fc * lbl_803DC4A4;
            velArg0 = velCalc0;
            arwarwing_setVelocity(*state, (int)&velArg0);
        }
        else
        {
            fc = (((AndrossState*)state)->savedPosZ - ((GameObject*)*state)->anim.localPosZ);
            fval = (lbl_803E74D4 < lbl_803E7514 * timeDelta + ((AndrossState*)state)->camOffsetAccum)
                       ? lbl_803E74D4
                       : lbl_803E7514 * timeDelta + ((AndrossState*)state)->camOffsetAccum;
            ((AndrossState*)state)->camOffsetAccum = fval;
            *(u8*)(state + 0x2e) = 0;
            *(s16*)(*state + 6) = *(s16*)(*state + 6) & ~0x4000;
            ref = (int)((f32)(s16)arwarwing_getRotY(*state) + fc * lbl_803DC4AC);
            arwarwing_setRotY(*state, ref);
            thrustA.x = lbl_803E74D4;
            thrustA.y = lbl_803E74D4;
            thrustA.z = (float)(fc * lbl_803DC4A8);
            thrustAArg = thrustA;
            arwarwing_setVelocity(*state, (int)&thrustAArg);
            if ((((AndrossState*)state)->soundEventFlags >> 5 & 1) == 0u)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_drak_pain1);
                ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f20 = 1;
            }
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
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
            ((AndrossState*)state)->fadeAlpha = lbl_803E74D4;
            ((AndrossState*)state)->actionState = 0x1f;
        }
        break;
    case 0x1f:
        break;
    }
    camActionParam = lbl_803E7584 + ((AndrossState*)state)->camOffsetAccum;
    (*gCameraInterface)->releaseAction(&camActionParam, 4);
    ((GameObject*)obj)->anim.velocityX = ((AndrossState*)state)->springStiffness *
                                             (((AndrossState*)state)->targetPosX - ((GameObject*)obj)->anim.localPosX) +
                                         ((GameObject*)obj)->anim.velocityX;
    ((GameObject*)obj)->anim.velocityY = ((AndrossState*)state)->springStiffness *
                                             (((AndrossState*)state)->targetPosY - ((GameObject*)obj)->anim.localPosY) +
                                         ((GameObject*)obj)->anim.velocityY;
    ((GameObject*)obj)->anim.velocityZ = ((AndrossState*)state)->springStiffness *
                                             (((AndrossState*)state)->targetPosZ - ((GameObject*)obj)->anim.localPosZ) +
                                         ((GameObject*)obj)->anim.velocityZ;
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * ((AndrossState*)state)->springDamping;
    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * ((AndrossState*)state)->springDamping;
    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * ((AndrossState*)state)->springDamping;
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + ((GameObject*)obj)->anim.velocityX;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + ((GameObject*)obj)->anim.velocityY;
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + ((GameObject*)obj)->anim.velocityZ;
    if (lbl_803E74D4 == ((AndrossState*)state)->velZ)
    {
        if (*(u8*)(state + 0x2e) != 0)
        {
            fn_8023A6A4((AndrossState*)state, lbl_803DC4B4, lbl_803DC4B8, lbl_803E74D4);
        }
        else
        {
            ((AndrossState*)state)->velZ =
                lbl_803DC4B0 * (((AndrossState*)state)->savedPosZ - ((GameObject*)*state)->anim.localPosZ);
        }
    }
    if (*(void**)(*state + 0xc0) == NULL)
    {
        velAdd = *(SunVec3*)(state + 0x36);
        arwarwing_addVelocity(*state, (int)&velAdd);
    }
    sval = ((AndrossState*)state)->targetRotX - (u16)((GameObject*)obj)->anim.rotX;
    if (0x8000 < sval)
    {
        sval = sval - 0xffff;
    }
    if (sval < -0x8000)
    {
        sval = sval + 0xffff;
    }
    ((AndrossState*)state)->rotXSpeed =
        (short)(((AndrossState*)state)->rotXSpeed +
                (((int)sval / lbl_803DC430 - (int)((AndrossState*)state)->rotXSpeed) / lbl_803DC434));
    ((AndrossState*)state)->rotYSpeed =
        (short)(((AndrossState*)state)->rotYSpeed +
                ((-(int)((GameObject*)obj)->anim.rotY / lbl_803DC430 - (int)((AndrossState*)state)->rotYSpeed) /
                 lbl_803DC434));
    ((GameObject*)obj)->anim.rotX += ((AndrossState*)state)->rotXSpeed;
    ((GameObject*)obj)->anim.rotY += ((AndrossState*)state)->rotYSpeed;
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, ((AndrossState*)state)->animSpeed, timeDelta, 0);
    fn_8023A3E4(obj, (int)state);
    fn_8023A87C((GameObject*)(obj), (int)state);
    ref = (int)((AndrossState*)state)->spawnedObj;
    if (*(void**)&((AndrossState*)state)->spawnedObj != NULL)
    {
        *(float*)&((AndrossState*)ref)->spawnedObj = *(float*)&((AndrossState*)ref)->spawnedObj - lbl_803E74D8;
        ((AndrossState*)state)->spawnedObjLifetime -= framesThisStep;
        if (((AndrossState*)state)->spawnedObjLifetime < 0)
        {
            Obj_FreeObject((int)((AndrossState*)state)->spawnedObj);
            ((AndrossState*)state)->spawnedObjLifetime = 0;
            ((AndrossState*)state)->spawnedObj = NULL;
        }
    }
    if (((AndrossState*)state)->fightPhase < 6)
    {
        searchDist0 = lbl_803E7490;
        ref = ObjList_FindNearestObjectByDefNo((GameObject*)(obj), 0x7e5, &searchDist0);
        if ((u32)ref != 0)
        {
            if (*(void**)&((AndrossState*)ref)->cachedPosX != NULL)
            {
                ref = *(int*)&((AndrossState*)ref)->cachedPosX;
            }
            if ((((AndrossState*)ref)->unk44 != 0x10) ||
                (found = animatedObjGetSeqId(((AndrossState*)ref)->seqQueryObj), found != 0x598))
            {
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 8) = ((GameObject*)obj)->anim.localPosX;
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 0xc) = ((GameObject*)obj)->anim.localPosY;
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 0x10) = ((GameObject*)obj)->anim.localPosZ;
            }
        }
        searchDist1 = lbl_803E7490;
        ref = ObjList_FindNearestObjectByDefNo((GameObject*)(obj), 0x1e, &searchDist1);
        if ((u32)ref != 0)
        {
            if (*(void**)&((AndrossState*)ref)->cachedPosX != NULL)
            {
                ref = *(int*)&((AndrossState*)ref)->cachedPosX;
            }
            if ((((AndrossState*)ref)->unk44 != 0x10) ||
                (found = animatedObjGetSeqId(((AndrossState*)ref)->seqQueryObj), found != 0x598))
            {
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 8) = ((GameObject*)obj)->anim.localPosX;
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 0xc) = ((GameObject*)obj)->anim.localPosY;
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 0x10) = ((GameObject*)obj)->anim.localPosZ;
            }
        }
        searchDist2 = lbl_803E7490;
        ref = ObjList_FindNearestObjectByDefNo((GameObject*)(obj), 0x76f, &searchDist2);
        if ((u32)ref != 0)
        {
            if (*(void**)&((AndrossState*)ref)->cachedPosX != NULL)
            {
                ref = *(int*)&((AndrossState*)ref)->cachedPosX;
            }
            if ((((AndrossState*)ref)->unk44 != 0x10) ||
                (found = animatedObjGetSeqId(((AndrossState*)ref)->seqQueryObj), found != 0x598))
            {
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 8) = ((GameObject*)obj)->anim.localPosX;
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 0xc) = ((GameObject*)obj)->anim.localPosY;
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 0x10) = ((GameObject*)obj)->anim.localPosZ;
            }
        }
        searchDist3 = lbl_803E7490;
        ref = ObjList_FindNearestObjectByDefNo((GameObject*)(obj), 0x814, &searchDist3);
        if ((u32)ref != 0)
        {
            if (*(void**)&((AndrossState*)ref)->cachedPosX != NULL)
            {
                ref = *(int*)&((AndrossState*)ref)->cachedPosX;
            }
            if ((((AndrossState*)ref)->unk44 != 0x10) ||
                (found = animatedObjGetSeqId(((AndrossState*)ref)->seqQueryObj), found != 0x598))
            {
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 8) = ((GameObject*)obj)->anim.localPosX;
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 0xc) = ((GameObject*)obj)->anim.localPosY;
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 0x10) = ((GameObject*)obj)->anim.localPosZ;
            }
        }
        searchDist = lbl_803E7490;
        ref = ObjList_FindNearestObjectByDefNo((GameObject*)(obj), 0x6cf, &searchDist);
        if ((u32)ref != 0)
        {
            if (*(void**)&((AndrossState*)ref)->cachedPosX != NULL)
            {
                ref = *(int*)&((AndrossState*)ref)->cachedPosX;
            }
            if ((((AndrossState*)ref)->unk44 != 0x10) ||
                (found = animatedObjGetSeqId(((AndrossState*)ref)->seqQueryObj), found != 0x598))
            {
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 8) = ((GameObject*)obj)->anim.localPosX;
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 0xc) = ((GameObject*)obj)->anim.localPosY;
                *(f32*)(((AndrossState*)ref)->targetPosPtr + 0x10) = ((GameObject*)obj)->anim.localPosZ;
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

f32 gAndrossMoveAnimSpeeds[23] = {
    0.01f, 0.01f, 0.005f, 0.005f, 0.08f, 0.007f, 0.007f, 0.007f, 0.007f, 0.007f, 0.007f, 0.007f,
    0.03f, 0.03f, 0.02f,  0.02f,  0.01f, 0.02f,  0.02f,  0.02f,  0.02f,  0.007f, 0.003f,
};
