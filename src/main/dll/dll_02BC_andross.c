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

#define GAMEBIT_ANDROSS_HIT_CUE_BASE 0x108 /* six consecutive random-hit cue bits */

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

int andross_getExtraSize(void) { return 0xec; }

int andross_getObjectTypeId(void) { return 0; }

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
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E74DC);
}

void andross_setPartSignal(int obj, int signal)
{
    int state;

    if ((void*)obj == NULL)
    {
        return;
    }
    state = *(int*)&((GameObject*)obj)->extra;
    ((AndrossState*)state)->signalFlags |= signal;
}

#pragma scheduling off
int andross_updateModelAlpha(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int i;
    f32 v;
    f32 alpha;
    int model;
    int op;

    *(f32*)(state + 0x68) = lbl_803E74D4;
    v = ((AndrossState*)state)->fadeAlpha;
    model = *(int*)Obj_GetActiveModel(obj);
    i = 0;
    alpha = gAndrossAlpha255 * v;
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
    ((AndrossState*)state)->unkB6 = 5;
    ((AndrossState*)state)->fightPhase = 1;
    ((AndrossState*)state)->prevFightPhase = -1;
    ((AndrossState*)state)->targetRotX = -0x8000;
    ((GameObject*)obj)->anim.rotX = -0x8000;
    ((AndrossState*)state)->spawnCooldown = gAndrossInitSpawnCooldown;
    ((AndrossState*)state)->unkA8 = lbl_803E74D4;
    ((AndrossState*)state)->springStiffness = gAndrossSpringStiffness;
    ((AndrossState*)state)->springDamping = gAndrossSpringDamping;
    ((AndrossState*)state)->unkBC = 1;
    ObjHits_SetTargetMask(obj, 4);
    ((GameObject*)obj)->animEventCallback = andross_updateModelAlpha;
    fn_8006CB50();
    i = Obj_GetActiveModel(obj);
    model = *(int*)i;
    for (i = 0, val = i; i < *(u8*)(model + 0xf8); i++)
    {
        *(u8*)(ObjModel_GetRenderOp(model, i) + 0x43) = val;
    }
    GameBit_Set(0xd, 0);
    unlockLevel(0, 0, 1);
}

void fn_8023A87C(int obj, int state)
{
    void* spawned;

    spawned = *(void**)&((AndrossState*)state)->effectHandle;
    if (spawned != NULL)
    {
        *(f32*)((char*)spawned + 0x14) -= lbl_803E74D8;
        ((AndrossState*)state)->effectLifetime -= framesThisStep;
        if (((AndrossState*)state)->effectLifetime < 0)
        {
            fn_8022F558(((AndrossState*)state)->effectHandle, 5);
            ((AndrossState*)state)->effectLifetime = 0;
            ((AndrossState*)state)->effectHandle = 0;
        }
    }
    else
    {
        f32 v = ((AndrossState*)state)->spawnCooldown;
        f32 zero = lbl_803E74D4;
        if (v >= zero)
        {
            ((AndrossState*)state)->spawnCooldown = v - timeDelta;
            if (((AndrossState*)state)->spawnCooldown < zero)
                fn_80239DD8(obj, state);
        }
        else if ((u32)GameBit_Get(0x12) != 0)
        {
            ((AndrossState*)state)->spawnCooldown = (f32)(int)
            randomGetRange(1, 0x14);
            GameBit_Set(0x12, 0);
        }
    }
}

int fn_8023A6A4(int state, f32 clampRange, f32 scale, f32 zVel)
{
    f32 val, ang;
    f32 dx, dy, dz, dist;
    int yaw;
    int result;
    f32 vel[3];

    result = 0;
    dx = ((AndrossState*)state)->cachedPosX - ((GameObject*)*(int*)state)->anim.localPosX;
    dy = ((AndrossState*)state)->cachedPosY - ((GameObject*)*(int*)state)->anim.localPosY;
    dz = ((AndrossState*)state)->cachedPosZ - ((GameObject*)*(int*)state)->anim.localPosZ;
    dist = sqrtf(dx * dx + dy * dy);
    yaw = (s16)getAngle(dx, dy);
    if ((s16)getAngle(dist, dz) > 0x2ee0 && dz > lbl_803DC4C0)
        result = 1;
    val = (dist / scale < -clampRange) ? -clampRange : ((dist / scale > clampRange) ? clampRange : dist / scale);
    ang = lbl_803E74A0 * yaw / lbl_803E74A4;
    ((AndrossState*)state)->velX = val * mathSinf(ang);
    ((AndrossState*)state)->velY = val * mathCosf(ang);
    arwarwing_getVelocity((int)vel, *(int*)state);
    ((AndrossState*)state)->velX -= vel[0] * gAndrossArwingVelDamp;
    ((AndrossState*)state)->velY -= vel[1] * gAndrossArwingVelDamp;
    ((AndrossState*)state)->velZ = zVel;
    return result;
}

void andross_update(int obj)
{
    int* state;
    u8 moveChanged;
    u8 stateChanged;
    u8 pathFlag;
    int work;
    int ref;
    u32 val;
    f32 fval;
    s16 sval;
    int found;
    s8 bval;
    s16 randVal;
    int objId;
    u8 signals;
    u8 flag;
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
    u32 randOffsetY;
    state = ((GameObject*)obj)->extra;
    moveChanged = 0;
    stateChanged = 0;
    pathFlag = 0;
    if (*(u8*)((int)state + 0xb6) != 0)
    {
        *(u8*)((int)state + 0xb6) -= 1;
        return;
    }
    if (*(void* *)&((AndrossState*)state)->handObjA == NULL)
    {
        found = ObjList_FindObjectById(0x47b78);
        ((AndrossState*)state)->handObjA = found;
    }
    if (*(void* *)&((AndrossState*)state)->handObjB == NULL)
    {
        found = ObjList_FindObjectById(0x47b6a);
        ((AndrossState*)state)->handObjB = found;
    }
    if (*(void* *)&((AndrossState*)state)->lightAnchorObj == NULL)
    {
        found = ObjList_FindObjectById(0x47dd9);
        ((AndrossState*)state)->lightAnchorObj = found;
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
    /*
     * spawnObj[val] (state+0x18+val*4) intentionally kept as the indexed raw
     * deref: the original sources the handle this way and the lwzx index reg
     * coloring only matches in this form. spawnDelta[val] (state+0x28+val*12)
     * is the typed SunVec3 array.
     */
    for (work = 0; (u8)work < 4; work = work + 1)
    {
        val = (u8)work;
        if (*(void**)((int)state + val * 4 + 0x18) == NULL)
        {
            *(int*)((int)state + val * 4 + 0x18) = ObjList_FindObjectById(gAndrossSpawnObjectIds[val]);
            if (*(void**)((int)state + val * 4 + 0x18) != NULL)
            {
                ((AndrossState*)state)->spawnDelta[val].x =
                    *(float*)(*(int*)((int)state + val * 4 + 0x18) + 0xc) - ((GameObject*)obj)->anim.localPosX;
                ((AndrossState*)state)->spawnDelta[val].y =
                    *(float*)(*(int*)((int)state + val * 4 + 0x18) + 0x10) - ((GameObject*)obj)->anim.localPosY;
                ((AndrossState*)state)->spawnDelta[val].z =
                    *(float*)(*(int*)((int)state + val * 4 + 0x18) + 0x14) - ((GameObject*)obj)->anim.localPosZ;
            }
        }
        else
        {
            *(float*)(*(int*)((int)state + val * 4 + 0x18) + 0xc) =
                ((GameObject*)obj)->anim.localPosX + ((AndrossState*)state)->spawnDelta[val].x;
            *(float*)(*(int*)((int)state + val * 4 + 0x18) + 0x10) =
                ((GameObject*)obj)->anim.localPosY + ((AndrossState*)state)->spawnDelta[val].y;
            *(float*)(*(int*)((int)state + val * 4 + 0x18) + 0x14) =
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
        pathFlag = 1;
    }
    ObjPath_GetPointWorldPosition(obj, pathFlag, (f32*)(state + 0x30), (f32*)(state + 0x31), (f32*)(state + 0x32), 0);
    if (pathFlag == 1)
    {
        fa = ((AndrossState*)state)->cachedPosY;
        fval = gAndrossPathPosOffset;
        ((AndrossState*)state)->cachedPosY = fa + fval;
        ((AndrossState*)state)->cachedPosZ = ((AndrossState*)state)->cachedPosZ + fval;
    }
    switch (((AndrossState*)state)->fightPhase)
    {
    case 1:
        if (stateChanged)
        {
            if (((AndrossState*)state)->unkBC != 0)
            {
                ((AndrossState*)state)->unkBC = 0;
            }
            else
            {
                androsshand_setState(((AndrossState*)state)->handObjA, 2, 1);
                androsshand_setState(((AndrossState*)state)->handObjB, 2, 1);
            }
            ((AndrossState*)state)->unkAE = 10;
            ((AndrossState*)state)->unkAF = 10;
            ((AndrossState*)state)->unkB0 = 10;
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
        if ((stateChanged) &&
            (((AndrossState*)state)->signalFlags = ((AndrossState*)state)->signalFlags & ~0x6,
                ((AndrossState*)state)->actionState == 0x16))
        {
            androsshand_setState(((AndrossState*)state)->handObjA, 1, 1);
            androsshand_setState(((AndrossState*)state)->handObjB, 1, 1);
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
            ((AndrossState*)state)->unkAE = 0xf;
            ((AndrossState*)state)->unkAF = 0xf;
            ((AndrossState*)state)->unkB0 = 0xf;
            ((AndrossState*)state)->actionState = 0;
            ((AndrossState*)state)->unkB7 = 0;
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
                ((AndrossState*)state)->unkB7++;
                if (((AndrossState*)state)->unkB7 > 3)
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
                ((AndrossState*)state)->actionToggle = ((AndrossState*)state)->actionToggle ^ 1;
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
    found = ((AndrossState*)state)->actionState;
    if (found != ((AndrossState*)state)->prevActionState)
    {
        moveChanged = 1;
    }
    ((AndrossState*)state)->prevActionState = found;
    switch (((AndrossState*)state)->actionState)
    {
    case 0:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[0];
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
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeX * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        ((AndrossState*)state)->durationTimer = ((AndrossState*)state)->durationTimer - timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        if ((u16)(val = ((AndrossState*)state)->unkAE, val += ((AndrossState*)state)->unkAF,
            val + ((AndrossState*)state)->unkB0) == 0)
        {
            ((AndrossState*)state)->fightPhase++;
            ((AndrossState*)state)->actionState = 5;
            ((AndrossState*)state)->actionPending = 0;
            GameBit_Set(0xd, 0);
        }
        break;
    case 1:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0xc, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[12];
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeX * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionState = 2;
            ((AndrossState*)state)->actionPending = 0;
        }
        if ((u16)(val = ((AndrossState*)state)->unkAE, val += ((AndrossState*)state)->unkAF,
            val + ((AndrossState*)state)->unkB0) == 0)
        {
            ((AndrossState*)state)->fightPhase++;
            ((AndrossState*)state)->actionState = 5;
            ((AndrossState*)state)->actionPending = 0;
            GameBit_Set(0xd, 0);
        }
        break;
    case 2:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0xe, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[14];
            ((AndrossState*)state)->durationTimer = lbl_803E74F0;
            ((AndrossState*)state)->actionTimer = 0xffff;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeX * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        Sfx_KeepAliveLoopedObjectSound(obj, 0x467);
        ((AndrossState*)state)->actionTimer -= framesThisStep;
        if (((AndrossState*)state)->actionTimer < 0)
        {
            fn_8023A268(obj, (int)state, 0);
            ((AndrossState*)state)->actionTimer = lbl_803DC43C;
        }
        ((AndrossState*)state)->durationTimer = ((AndrossState*)state)->durationTimer - timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            ((AndrossState*)state)->actionState = 3;
            ((AndrossState*)state)->actionPending = 0;
        }
        if ((u16)(val = ((AndrossState*)state)->unkAE, val += ((AndrossState*)state)->unkAF,
            val + ((AndrossState*)state)->unkB0) == 0)
        {
            ((AndrossState*)state)->fightPhase++;
            ((AndrossState*)state)->actionState = 5;
            ((AndrossState*)state)->actionPending = 0;
            GameBit_Set(0xd, 0);
        }
        break;
    case 3:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0xd, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[13];
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeX * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 4:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[0];
            GameBit_Set(0xd, 1);
            ((AndrossState*)state)->durationTimer = lbl_803E7504;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeX * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        ((AndrossState*)state)->durationTimer = ((AndrossState*)state)->durationTimer - timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            ((AndrossState*)state)->actionPending = 1;
            GameBit_Set(0xd, 0);
        }
        if ((u16)(val = ((AndrossState*)state)->unkAE, val += ((AndrossState*)state)->unkAF,
            val + ((AndrossState*)state)->unkB0) == 0)
        {
            ((AndrossState*)state)->fightPhase++;
            ((AndrossState*)state)->actionState = 5;
            ((AndrossState*)state)->actionPending = 0;
            GameBit_Set(0xd, 0);
        }
        break;
    case 0x15:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[0];
            GameBit_Set(0xd, 1);
            ((AndrossState*)state)->durationTimer = lbl_803E7504;
        }
        for (ref = 0; (u8)ref < 6; ref = ref + 1)
        {
            if ((u32)GameBit_Get((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
            {
                ((AndrossState*)state)->timer = 0x3c;
                goto LAB_8023bb18;
            }
        }
        ((AndrossState*)state)->timer -= framesThisStep;
        if (((AndrossState*)state)->timer <= 0)
        {
            ref = randomGetRange(0, 5);
            GameBit_Set(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
            ((AndrossState*)state)->timer = 0x3c;
        }
    LAB_8023bb18:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeX * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        ((AndrossState*)state)->durationTimer = ((AndrossState*)state)->durationTimer - timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            ((AndrossState*)state)->actionPending = 1;
            GameBit_Set(0xd, 0);
        }
        break;
    case 6:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[0];
            androsshand_setState(((AndrossState*)state)->handObjB, 4, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E7508) ? lbl_803E7508 : ((fb > lbl_803E750C) ? lbl_803E750C : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
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
        if (moveChanged)
        {
            androsshand_setState(((AndrossState*)state)->handObjA, 4, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E7508) ? lbl_803E7508 : ((fb > lbl_803E750C) ? lbl_803E750C : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
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
        if (moveChanged)
        {
            androsshand_setState(((AndrossState*)state)->handObjA, 6, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeX * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
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
        if (moveChanged)
        {
            androsshand_setState(((AndrossState*)state)->handObjB, 6, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7500) ? lbl_803E7500 : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeX * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
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
                Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? 0x471 : 0x472);
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
            fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX))
                / lbl_803E74A4));
            ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa +
                (float)(((AndrossState*)state)->homePosX + fc));
            fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY))
                / lbl_803E74A4));
            ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
                (float)(((AndrossState*)state)->homePosY + fb));
            ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
            if (moveChanged)
            {
                androsshand_setState(((AndrossState*)state)->handObjA, 5, 0);
                androsshand_setState(((AndrossState*)state)->handObjB, 5, 0);
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
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[1];
            if (((AndrossState*)state)->fightPhase < 5)
            {
                androsshand_setState(((AndrossState*)state)->handObjA, 0, 0);
                androsshand_setState(((AndrossState*)state)->handObjB, 0, 0);
            }
            else
            {
                androsshand_setState(((AndrossState*)state)->handObjA, 9, 1);
                androsshand_setState(((AndrossState*)state)->handObjB, 9, 1);
                ((AndrossState*)state)->signalFlags = ((AndrossState*)state)->signalFlags | 6;
            }
        }
        if ((((AndrossState*)state)->fightPhase == 5) && (((AndrossState*)state)->actionState == 0xb))
        {
            for (ref = 0; (u8)ref < 6; ref = ref + 1)
            {
                if ((u32)GameBit_Get((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    ((AndrossState*)state)->timer = 0x3c;
                    goto LAB_8023c584;
                }
            }
            ((AndrossState*)state)->timer -= framesThisStep;
            if (((AndrossState*)state)->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                GameBit_Set(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                ((AndrossState*)state)->timer = 0x3c;
            }
        }
    LAB_8023c584:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E7510) ? lbl_803E7510 : ((fb > gAndrossSwayAmplitudeY) ? gAndrossSwayAmplitudeY : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeY * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (lbl_803E7514 * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            switch (((AndrossState*)state)->actionState)
            {
            case 0xd:
                ((AndrossState*)state)->actionState = 0xe;
                break;
            default:
            case 0xb:
            case 0xc:
            case 0xe:
                ((AndrossState*)state)->actionState = 0xc;
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
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[2];
            ((AndrossState*)state)->unkB1[0] = 0;
            GameBit_Set(0x10, 0);
            ((AndrossState*)state)->actionTimer = lbl_803DC44C;
            ((AndrossState*)state)->durationTimer = lbl_803E74D4;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E7508) ? lbl_803E7508 : ((fa > lbl_803E750C) ? lbl_803E750C : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeY * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (lbl_803E7514 * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        fn_8023A6A4((int)state, lbl_803DC440, lbl_803DC444, lbl_803DC448);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x466);
        if ((((AndrossState*)state)->actionTimer != 0) &&
            (((AndrossState*)state)->actionTimer -= framesThisStep,
                ((AndrossState*)state)->actionTimer <= 0))
        {
            ((AndrossState*)state)->actionTimer = 0;
            GameBit_Set(0xf, 1);
        }
        ((AndrossState*)state)->durationTimer = ((AndrossState*)state)->durationTimer - timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            fn_80239FCC(obj, (int)state);
            ((AndrossState*)state)->durationTimer = ((AndrossState*)state)->durationTimer + (f32)(lbl_803DC450);
        }
        fn_80239EAC(obj, (int)state);
        if ((u32)GameBit_Get(0x10) != 0)
        {
            GameBit_Set(0x10, 0);
            ((AndrossState*)state)->actionState = 0x1a;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossDistortPhaseWrap)
            {
                gAndrossDistortPhase = fval - gAndrossDistortPhaseWrap;
            }
            turnOnDistortionFilter((f32*)(state + 0x30), lbl_803E74BC, &gAndrossDistortFilterParam, gAndrossDistortPhase);
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
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[2];
            if (((AndrossState*)state)->fightPhase < 5)
            {
                ((AndrossState*)state)->unkB1[0] = 1;
            }
            ((AndrossState*)state)->actionTimer = lbl_803DC460;
            ((AndrossState*)state)->durationTimer = lbl_803E74D4;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, 0x466);
        if (((AndrossState*)state)->fightPhase == 5)
        {
            for (ref = 0; (u8)ref < 6; ref = ref + 1)
            {
                if ((u32)GameBit_Get((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    ((AndrossState*)state)->timer = 0x3c;
                    goto LAB_8023cbdc;
                }
            }
            ((AndrossState*)state)->timer -= framesThisStep;
            if (((AndrossState*)state)->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                GameBit_Set(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                ((AndrossState*)state)->timer = 0x3c;
            }
        }
    LAB_8023cbdc:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74F4) ? lbl_803E74F4 : ((fb > lbl_803E74F8) ? lbl_803E74F8 : fb);
        fb = (fa < lbl_803E7510) ? lbl_803E7510 : ((fa > gAndrossSwayAmplitudeY) ? gAndrossSwayAmplitudeY : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeY * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (lbl_803E7514 * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        bval = fn_8023A6A4((int)state, lbl_803DC454, lbl_803DC458, lbl_803DC45C);
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
            turnOnDistortionFilter((f32*)(state + 0x30), lbl_803E74BC, &gAndrossDistortFilterParam, gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        ((AndrossState*)state)->durationTimer = ((AndrossState*)state)->durationTimer - timeDelta;
        if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
        {
            fn_80239FCC(obj, (int)state);
            ((AndrossState*)state)->durationTimer = ((AndrossState*)state)->durationTimer + (f32)(lbl_803DC464);
        }
        fn_80239EAC(obj, (int)state);
        if (((AndrossState*)state)->unkB5 != 0)
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
            turnOnDistortionFilter((f32*)(state + 0x30), lbl_803E74BC, &gAndrossDistortFilterParam, gAndrossDistortPhase);
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
                turnOnDistortionFilter((f32*)(state + 0x30), lbl_803E74BC, &gAndrossDistortFilterParam, gAndrossDistortPhase);
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
            turnOnDistortionFilter((f32*)(state + 0x30), lbl_803E74BC, &gAndrossDistortFilterParam, gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    case 0xf:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x10, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[16];
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E7500) ? lbl_803E7500 : ((fb > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x10:
        if (moveChanged)
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
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74D4 * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (lbl_803E74D4 * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        ref = *state;
        velCalc3.x = (((AndrossState*)state)->cachedPosX - *(float*)&((AndrossState*)ref)->lightAnchorObj) *
            lbl_803DC468;
        velCalc3.y = (((AndrossState*)state)->cachedPosY - *(float*)&((AndrossState*)ref)->effectHandle) * lbl_803DC468;
        velCalc3.z = (((AndrossState*)state)->cachedPosZ - *(float*)&((AndrossState*)ref)->unk14) * lbl_803DC468;
        velArg3 = velCalc3;
        arwarwing_setVelocity(ref, (int)&velArg3);
        fval = (lbl_803E74EC < -(lbl_803E74B0 * timeDelta - ((AndrossState*)state)->unkA8)) ? -(lbl_803E74B0 * timeDelta - ((AndrossState*)state)->unkA8) : lbl_803E74EC;
        ((AndrossState*)state)->unkA8 = fval;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            *(s16*)(*state + 6) = *(s16*)(*state + 6) | 0x4000;
            ((AndrossState*)state)->actionState = 0x11;
        }
        break;
    case 0x11:
        if (moveChanged)
        {
            Sfx_PlayFromObject(obj, 0x468);
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x15, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[21];
            arwarwing_addShield(*state, 0xfffffffc);
        }
        fval = (lbl_803E74EC < -(lbl_803E74B0 * timeDelta - ((AndrossState*)state)->unkA8)) ? -(lbl_803E74B0 * timeDelta - ((AndrossState*)state)->unkA8) : lbl_803E74EC;
        ((AndrossState*)state)->unkA8 = fval;
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        zero = lbl_803E74D4;
        fc = (fb < zero) ? zero : ((fb > zero) ? zero : fb);
        zero = *(f32*)&lbl_803E74D4;
        fb = (fa < zero) ? zero : ((fa > zero) ? zero : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74D4 * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (lbl_803E74D4 * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x12:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x12, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[18];
            androsshand_setState(((AndrossState*)state)->handObjA, 0, 0);
            androsshand_setState(((AndrossState*)state)->handObjB, 0, 0);
            if ((((AndrossState*)state)->fightPhase == 5) && (((AndrossState*)state)->actionToggle != 0))
            {
                GameBit_Set(0xe, 1);
            }
        }
        ((AndrossState*)state)->fadeAlpha = ((AndrossState*)state)->fadeAlpha - gAndrossFadeAlphaStep;
        fval = (lbl_803E74D4 < ((AndrossState*)state)->fadeAlpha) ? ((AndrossState*)state)->fadeAlpha : lbl_803E74D4;
        ((AndrossState*)state)->fadeAlpha = fval;
        fc = ((AndrossState*)state)->fadeAlpha;
        work = *(int*)Obj_GetActiveModel(obj);
        ref = 0;
        fval = gAndrossAlpha255 * fc;
        for (; ref < (int)(u32) * (u8*)(work + 0xf8); ref = ref + 1)
        {
            found = ObjModel_GetRenderOp(work, ref);
            ((AndrossState*)found)->unk43 = fval;
        }
        if ((((AndrossState*)state)->fightPhase == 5) && (((AndrossState*)state)->actionToggle == 0))
        {
            for (ref = 0; (u8)ref < 6; ref = ref + 1)
            {
                if ((u32)GameBit_Get((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    ((AndrossState*)state)->timer = 0x3c;
                    goto LAB_8023d59c;
                }
            }
            ((AndrossState*)state)->timer -= framesThisStep;
            if (((AndrossState*)state)->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                GameBit_Set(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                ((AndrossState*)state)->timer = 0x3c;
            }
        }
    LAB_8023d59c:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E74F4) ? lbl_803E74F4 : ((fa > lbl_803E74F8) ? lbl_803E74F8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionState = 0x13;
        }
        break;
    case 0x13:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[19];
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
        Sfx_KeepAliveLoopedObjectSound(obj, 0x469);
        if ((((AndrossState*)state)->fightPhase == 5) && (((AndrossState*)state)->actionToggle == 0))
        {
            for (ref = 0; (u8)ref < 6; ref = ref + 1)
            {
                if ((u32)GameBit_Get((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    ((AndrossState*)state)->timer = 0x3c;
                    goto LAB_8023d7cc;
                }
            }
            ((AndrossState*)state)->timer -= framesThisStep;
            if (((AndrossState*)state)->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                GameBit_Set(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                ((AndrossState*)state)->timer = 0x3c;
            }
        }
    LAB_8023d7cc:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E7520) ? lbl_803E7520 : ((fb > lbl_803E74A8) ? lbl_803E74A8 : fb);
        fb = (fa < lbl_803E7524) ? lbl_803E7524 : ((fa > lbl_803E7528) ? lbl_803E7528 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (lbl_803E74E8 * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        ((AndrossState*)state)->actionTimer -= framesThisStep;
        ref = (int)((AndrossState*)state)->durationTimer;
        ((AndrossState*)state)->durationTimer = ((AndrossState*)state)->durationTimer - framesThisStep;
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
        for (work = 0; (u8)work < 2; work = work + 1)
        {
            if (((((void*)((AndrossState*)state)->unk14 == NULL) && (((AndrossState*)state)->actionTimer <= delayPair[(u8)work]))
                &&
                ((short)ref > delayPair[(u8)work])) && (Obj_IsLoadingLocked() != 0))
            {
                found = Obj_AllocObjectSetup(0x24, 0x819);
                *(f32*)&((AndrossState*)found)->handObjB = ((AndrossState*)state)->cachedPosX;
                *(f32*)&((AndrossState*)found)->lightAnchorObj = ((AndrossState*)state)->cachedPosY;
                *(f32*)&((AndrossState*)found)->effectHandle = ((AndrossState*)state)->cachedPosZ;
                *(u8*)(found + 4) = 1;
                *(u8*)(found + 5) = 1;
                ((AndrossState*)found)->unk20 = 0xffff;
                found = ((int(*)(int,int))loadObjectAtObject)(obj, found);
                ((AndrossState*)state)->unk14 = found;
                if ((void*)((AndrossState*)state)->unk14 != NULL)
                {
                    ((GameObject*)((AndrossState*)state)->unk14)->anim.alpha = 0xff;
                    *(u8*)(((AndrossState*)state)->unk14 + 0x37) = 0xff;
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
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x14, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[20];
        }
        if ((((AndrossState*)state)->fightPhase == 5) && (((AndrossState*)state)->actionToggle == 0))
        {
            for (ref = 0; (u8)ref < 6; ref = ref + 1)
            {
                if ((u32)GameBit_Get((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    ((AndrossState*)state)->timer = 0x3c;
                    goto LAB_8023db24;
                }
            }
            ((AndrossState*)state)->timer -= framesThisStep;
            if (((AndrossState*)state)->timer <= 0)
            {
                ref = randomGetRange(0, 5);
                GameBit_Set(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                ((AndrossState*)state)->timer = 0x3c;
            }
        }
    LAB_8023db24:
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (((GameObject*)*state)->anim.localPosX - ((AndrossState*)state)->homePosX);
        fa = (((GameObject*)*state)->anim.localPosY - ((AndrossState*)state)->homePosY);
        fc = (fb < lbl_803E74EC) ? lbl_803E74EC : ((fb > lbl_803E74F0) ? lbl_803E74F0 : fb);
        fb = (fa < lbl_803E752C) ? lbl_803E752C : ((fa > lbl_803E74E8) ? lbl_803E74E8 : fa);
        fa = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseX)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosX = (gAndrossSwayAmplitudeX * fa +
            (float)(((AndrossState*)state)->homePosX + fc));
        fc = mathSinf(((lbl_803E74A0 * (f32)(gAndrossSwayPhaseY)) /
            lbl_803E74A4));
        ((AndrossState*)state)->targetPosY = (gAndrossSwayAmplitudeY * fc +
            (float)(((AndrossState*)state)->homePosY + fb));
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x19:
    case 0x1a:
        if (moveChanged)
        {
            Sfx_PlayFromObject(obj, 0x4a6);
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[4];
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x1b:
        if (moveChanged)
        {
            GameBit_Set(0x10, 0);
            ((AndrossState*)state)->actionTimer = 0x1e;
            arwarwing_resetFlightState(*state);
            ((GameObject*)*state)->anim.localPosZ = ((AndrossState*)state)->savedPosZ;
            ((AndrossState*)state)->unkA8 = lbl_803E74D4;
        }
        ((AndrossState*)state)->targetPosX = ((AndrossState*)state)->homePosX;
        ((AndrossState*)state)->targetPosY = ((AndrossState*)state)->homePosY;
        ((AndrossState*)state)->targetPosZ = ((AndrossState*)state)->homePosZ;
        if (((u32)GameBit_Get(0x10) != 0) && (((AndrossState*)state)->actionTimer-- == 0))
        {
            GameBit_Set(0x10, 0);
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x1c:
        if (moveChanged)
        {
            androssbrain_setState(((AndrossState*)state)->lightAnchorObj, 1, 0);
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
        ((AndrossState*)state)->fadeAlpha = ((AndrossState*)state)->fadeAlpha + gAndrossFadeAlphaStep;
        fval = ((AndrossState*)state)->fadeAlpha;
        fval = (gAndrossFadeAlphaMax < fval) ? gAndrossFadeAlphaMax : fval;
        ((AndrossState*)state)->fadeAlpha = fval;
        for (ref = 0; (u8)ref < 6; ref = ref + 1)
        {
            if ((u32)GameBit_Get((u8)ref + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
            {
                ((AndrossState*)state)->timer = 0x3c;
                goto LAB_8023de5c;
            }
        }
        ((AndrossState*)state)->timer -= framesThisStep;
        if (((AndrossState*)state)->timer <= 0)
        {
            ref = randomGetRange(0, 5);
            GameBit_Set(ref + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
            ((AndrossState*)state)->timer = 0x3c;
        }
    LAB_8023de5c:
        ((AndrossState*)state)->actionTimer -= framesThisStep;
        if (((AndrossState*)state)->actionTimer < 0)
        {
            ((AndrossState*)state)->durationTimer = ((AndrossState*)state)->durationTimer - lbl_803E74DC;
            if (((AndrossState*)state)->durationTimer < lbl_803E74D4)
            {
                *(char*)&((AndrossState*)state)->actionToggle = *(char*)&((AndrossState*)state)->actionToggle + '\x01';
                if (((AndrossState*)state)->actionToggle > 3)
                {
                    ((AndrossState*)state)->fightPhase = 5;
                    ((AndrossState*)state)->prevFightPhase = 5;
                    ((AndrossState*)state)->actionToggle = 0;
                    ((AndrossState*)state)->actionState = 0x12;
                    androssbrain_setState(((AndrossState*)state)->lightAnchorObj, 0, 0);
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
                val = randomGetRange((int)-gAndrossSpawnRandX, gAndrossSpawnRandX);
                ((AndrossState*)state)->targetPosX = (f32)(int)val +
                ((AndrossState*)state)->homePosX;
                randOffsetY = randomGetRange((int)-gAndrossSpawnRandY, gAndrossSpawnRandY);
                ((AndrossState*)state)->targetPosY = (f32)(int)randOffsetY +
                ((AndrossState*)state)->homePosY;
                val = randomGetRange((int)-gAndrossSpawnRandZ, gAndrossSpawnRandZ);
                ((AndrossState*)state)->targetPosZ = (f32)(int)val +
                ((AndrossState*)state)->homePosZ;
            }
        }
        if ((((AndrossState*)state)->signalFlags & 8) != 0)
        {
            arwingHudSetVisible(2);
            GameBit_Set(1, 1);
            GameBit_Set(0x4b1, 1);
            ((AndrossState*)state)->actionState = 0x1e;
            unlockLevel(0, 0, 1);
            objId = mapGetDirIdx(0xb);
            mapUnload(objId, 0x20000000);
            Music_Trigger(0xf3, 0);
        }
        fc = ((AndrossState*)state)->fadeAlpha;
        work = *(int*)Obj_GetActiveModel(obj);
        ref = 0;
        fval = gAndrossAlpha255 * fc;
        for (; ref < (int)(u32) * (u8*)(work + 0xf8); ref = ref + 1)
        {
            found = ObjModel_GetRenderOp(work, ref);
            ((AndrossState*)found)->unk43 = fval;
        }
        break;
    case 0x1d:
        if (moveChanged)
        {
            androssbrain_setState(((AndrossState*)state)->lightAnchorObj, 1, 0);
            ObjHits_DisableObject(obj);
            ((AndrossState*)state)->actionTimer = lbl_803DC484;
            ((AndrossState*)state)->targetPosX = ((GameObject*)*state)->anim.localPosX;
            ((AndrossState*)state)->targetPosY = ((GameObject*)*state)->anim.localPosY + gAndrossSpawnOffsetY;
            ((AndrossState*)state)->targetPosZ = ((GameObject*)*state)->anim.localPosZ + gAndrossSpawnOffsetZ;
            fval = lbl_803E74D4;
            ((GameObject*)obj)->anim.velocityX = lbl_803E74D4;
            ((GameObject*)obj)->anim.velocityY = fval;
            ((GameObject*)obj)->anim.velocityZ = fval;
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? 0x471 : 0x472);
        }
        ((AndrossState*)state)->actionTimer -= framesThisStep;
        if (((AndrossState*)state)->actionTimer < 0)
        {
            ((AndrossState*)state)->actionState = 0x1c;
        }
        break;
    case 0x16:
        if (moveChanged)
        {
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? 0x471 : 0x472);
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[0];
        }
        if (*(u8*)(state + 0x2e) != 0)
        {
            ref = *state;
            velCalc2.x = (((AndrossState*)state)->cachedPosX - *(float*)&((AndrossState*)ref)->lightAnchorObj) *
                lbl_803DC488;
            velCalc2.y = (((AndrossState*)state)->cachedPosY - *(float*)&((AndrossState*)ref)->effectHandle) *
                lbl_803DC488;
            velCalc2.z = (((AndrossState*)state)->cachedPosZ - *(float*)&((AndrossState*)ref)->unk14) * lbl_803DC488;
            velArg2 = velCalc2;
            arwarwing_setVelocity(ref, (int)&velArg2);
            fval = (lbl_803E7538 < -(lbl_803E753C * timeDelta - ((AndrossState*)state)->unkA8)) ? -(lbl_803E753C * timeDelta - ((AndrossState*)state)->unkA8) : lbl_803E7538;
            ((AndrossState*)state)->unkA8 = fval;
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
            bval = *(char*)(*(int*)(((AndrossState*)state)->handObjA + 0xb8) + 0x23);
            if ((((bval != 2) && (bval != 1)) &&
                    (bval = *(char*)(*(int*)(((AndrossState*)state)->handObjB + 0xb8) + 0x23), bval != 2)) &&
                (bval != 1))
            {
                ((AndrossState*)state)->actionPending = 1;
            }
        }
        break;
    case 5:
        ref = *(int*)(((AndrossState*)state)->handObjA + 0xb8);
        found = *(int*)(((AndrossState*)state)->handObjB + 0xb8);
        if (moveChanged)
        {
            Sfx_PlayFromObject(obj, 0x470);
            work = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x16, lbl_803E74D4, 0);
            *(f32*)(work + 100) = lbl_8032C098[22];
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f80 = 0;
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f40 = 0;
        }
        fc = ((GameObject*)obj)->anim.currentMoveProgress;
        if (fc < lbl_803E7540)
        {
            fc = mathSinf(((lbl_803E74A0 *
                    (float)(lbl_803E7548 *
                        (lbl_803E7550 * (fc / lbl_803E7540)))) /
                lbl_803E74A4));
            ((AndrossState*)state)->targetPosZ = (lbl_803E74A8 * fc + ((AndrossState*)state)->homePosZ);
        }
        else
        {
            fc = mathSinf(((lbl_803E74A0 *
                (float)(lbl_803E7548 *
                    (lbl_803E7558 *
                        ((fc - lbl_803E7540) / lbl_803E7560)
                        + lbl_803E7550))) / lbl_803E74A4));
            ((AndrossState*)state)->targetPosZ = ((f32)(lbl_803DC48C) * fc +
                ((AndrossState*)state)->homePosZ);
        }
        if ((((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7568) &&
            ((((AndrossState*)state)->soundEventFlags >> 6 & 1) == 0u))
        {
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? 0x471 : 0x472);
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f40 = 1;
        }
        if ((((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7570) && (((AndrossFlagByte*)&((AndrossState*)state)
            ->soundEventFlags)->f80 == 0))
        {
            Sfx_PlayFromObject(obj, 0x46d);
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f80 = 1;
        }
        bval = *(char*)&((AndrossState*)ref)->unk23;
        if ((((bval != 2) && (bval != 1)) &&
            (bval = *(char*)&((AndrossState*)found)->unk23, bval != 2)) && (bval != 1))
        {
            if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
            {
                ((AndrossState*)state)->actionPending = 1;
            }
            else if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E7568)
            {
                ((AndrossState*)state)->targetRotX = 0;
                androsshand_setState(((AndrossState*)state)->handObjA, 1,
                                     (u8)((((AndrossState*)state)->fightPhase == 4) + 1));
                androsshand_setState(((AndrossState*)state)->handObjB, 1,
                                     (u8)((((AndrossState*)state)->fightPhase == 4) + 1));
                ((AndrossState*)state)->signalFlags = ((AndrossState*)state)->signalFlags & ~0x6;
            }
        }
        break;
    case 0x17:
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 3, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[3];
            ((AndrossState*)state)->soundTimer = lbl_803E74D4;
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f20 = 0;
        }
        ((AndrossState*)state)->soundTimer = ((AndrossState*)state)->soundTimer + timeDelta;
        if ((((AndrossState*)state)->soundTimer > lbl_803E7578) && ((((AndrossState*)state)->soundEventFlags >> 5 & 1) == 0u))
        {
            Sfx_PlayFromObject(obj, 0x46f);
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f20 = 1;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress <= lbl_803DC490)
        {
            ((AndrossState*)state)->cachedPosX = ((GameObject*)obj)->anim.localPosX;
            ((AndrossState*)state)->cachedPosY = ((GameObject*)obj)->anim.localPosY - gAndrossCachedPosOffsetY;
            ((AndrossState*)state)->cachedPosZ = ((GameObject*)obj)->anim.localPosZ - gAndrossCachedPosOffsetZ;
            ref = *state;
            velCalc1.x = (((AndrossState*)state)->cachedPosX - *(float*)&((AndrossState*)ref)->lightAnchorObj) *
                lbl_803DC494;
            velCalc1.y = (((AndrossState*)state)->cachedPosY - *(float*)&((AndrossState*)ref)->effectHandle) *
                lbl_803DC494;
            velCalc1.z = (((AndrossState*)state)->cachedPosZ - *(float*)&((AndrossState*)ref)->unk14) * lbl_803DC494;
            velArg1 = velCalc1;
            arwarwing_setVelocity(ref, (int)&velArg1);
        }
        else
        {
            fc = (((AndrossState*)state)->savedPosZ - ((GameObject*)*state)->anim.localPosZ);
            fval = (lbl_803E74D4 < lbl_803E753C * timeDelta + ((AndrossState*)state)->unkA8) ? lbl_803E74D4 : lbl_803E753C * timeDelta + ((AndrossState*)state)->unkA8;
            ((AndrossState*)state)->unkA8 = fval;
            *(u8*)(state + 0x2e) = 0;
            *(s16*)(*state + 6) = *(s16*)(*state + 6) & ~0x4000;
            sval = arwarwing_getRotY(*state);
            ref = (int)(fc * lbl_803DC49C + (f32)(sval));
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
        if (moveChanged)
        {
            ref = *(int*)&((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E74D4, 0);
            ((AndrossState*)ref)->animSpeed = lbl_8032C098[17];
            ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f20 = 0;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress <= lbl_803DC4A0)
        {
            ref = *state;
            velCalc0.x = (((AndrossState*)state)->cachedPosX - *(float*)&((AndrossState*)ref)->lightAnchorObj) *
                lbl_803DC4A4;
            velCalc0.y = (((AndrossState*)state)->cachedPosY - *(float*)&((AndrossState*)ref)->effectHandle) *
                lbl_803DC4A4;
            velCalc0.z = (((AndrossState*)state)->cachedPosZ - *(float*)&((AndrossState*)ref)->unk14) * lbl_803DC4A4;
            velArg0 = velCalc0;
            arwarwing_setVelocity(ref, (int)&velArg0);
        }
        else
        {
            fc = (((AndrossState*)state)->savedPosZ - ((GameObject*)*state)->anim.localPosZ);
            fval = lbl_803E7514 * timeDelta + ((AndrossState*)state)->unkA8;
            if (lbl_803E74D4 < fval)
            {
                fval = lbl_803E74D4;
            }
            ((AndrossState*)state)->unkA8 = fval;
            *(u8*)(state + 0x2e) = 0;
            *(s16*)(*state + 6) = *(s16*)(*state + 6) & ~0x4000;
            sval = arwarwing_getRotY(*state);
            ref = (int)(fc * lbl_803DC4AC + (f32)(sval));
            arwarwing_setRotY(*state, ref);
            thrustA.x = lbl_803E74D4;
            thrustA.y = lbl_803E74D4;
            thrustA.z = (float)(fc * lbl_803DC4A8);
            thrustAArg = thrustA;
            arwarwing_setVelocity(*state, (int)&thrustAArg);
            if ((((AndrossState*)state)->soundEventFlags >> 5 & 1) == 0u)
            {
                Sfx_PlayFromObject(obj, 0x46f);
                ((AndrossFlagByte*)&((AndrossState*)state)->soundEventFlags)->f20 = 1;
            }
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E74DC)
        {
            ((AndrossState*)state)->actionPending = 1;
        }
        break;
    case 0x1e:
        ref = GameBit_Get(2);
        if ((((u32)ref != 0) || (ref = GameBit_Get(3), (u32)ref != 0)) ||
            (ref = GameBit_Get(4), (u32)ref != 0))
        {
            GameBit_Set(0x405, 0);
            (*gMapEventInterface)->setMapAct(0xb, 7);
            unlockLevel(0, 0, 1);
            loadMapAndParent(mapGetDirIdx(0xb));
            objId = mapGetDirIdx(0xb);
            lockLevel(objId, 1);
            warpToMap(0x4e, 0);
            ((AndrossState*)state)->fadeAlpha = lbl_803E74D4;
            ((AndrossState*)state)->actionState = 0x1f;
        }
        break;
    case 0x1f:
        break;
    }
    camActionParam = lbl_803E7584 + ((AndrossState*)state)->unkA8;
    (*gCameraInterface)->releaseAction(&camActionParam, 4);
    ((GameObject*)obj)->anim.velocityX =
        ((AndrossState*)state)->springStiffness * (((AndrossState*)state)->targetPosX - ((GameObject*)obj)->anim.
            localPosX) +
        ((GameObject*)obj)->anim.velocityX;
    ((GameObject*)obj)->anim.velocityY =
        ((AndrossState*)state)->springStiffness * (((AndrossState*)state)->targetPosY - ((GameObject*)obj)->anim.
            localPosY) +
        ((GameObject*)obj)->anim.velocityY;
    ((GameObject*)obj)->anim.velocityZ =
        ((AndrossState*)state)->springStiffness * (((AndrossState*)state)->targetPosZ - ((GameObject*)obj)->anim.
            localPosZ) +
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
            fn_8023A6A4((int)state, lbl_803DC4B4, lbl_803DC4B8, lbl_803E74D4);
        }
        else
        {
            ((AndrossState*)state)->velZ = lbl_803DC4B0 * (((AndrossState*)state)->savedPosZ - ((GameObject*)*state)->anim.localPosZ);
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
    ((AndrossState*)state)->rotXSpeed = (short)(((AndrossState*)state)->rotXSpeed +
        (((int)sval / lbl_803DC430 - (int)((AndrossState*)state)->rotXSpeed) / lbl_803DC434));
    ((AndrossState*)state)->rotYSpeed = (short)(((AndrossState*)state)->rotYSpeed +
        ((-(int)((GameObject*)obj)->anim.rotY / lbl_803DC430 - (int)((AndrossState*)state)->rotYSpeed) /
            lbl_803DC434));
    ((GameObject*)obj)->anim.rotX += ((AndrossState*)state)->rotXSpeed;
    ((GameObject*)obj)->anim.rotY += ((AndrossState*)state)->rotYSpeed;
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, ((AndrossState*)state)->animSpeed, timeDelta, 0);
    fn_8023A3E4(obj, (int)state);
    fn_8023A87C(obj, (int)state);
    ref = ((AndrossState*)state)->unk14;
    if (*(void**)&((AndrossState*)state)->unk14 != NULL)
    {
        *(float*)&((AndrossState*)ref)->unk14 = *(float*)&((AndrossState*)ref)->unk14 - lbl_803E74D8;
        ((AndrossState*)state)->spawnedObjLifetime = ((AndrossState*)state)->spawnedObjLifetime - framesThisStep;
        if (((AndrossState*)state)->spawnedObjLifetime < 0)
        {
            Obj_FreeObject(((AndrossState*)state)->unk14);
            ((AndrossState*)state)->spawnedObjLifetime = 0;
            ((AndrossState*)state)->unk14 = 0;
        }
    }
    if (((AndrossState*)state)->fightPhase < 6)
    {
        searchDist0 = lbl_803E7490;
        ref = ObjList_FindNearestObjectByDefNo(obj, 0x7e5, &searchDist0);
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
        ref = ObjList_FindNearestObjectByDefNo(obj, 0x1e, &searchDist1);
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
        ref = ObjList_FindNearestObjectByDefNo(obj, 0x76f, &searchDist2);
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
        ref = ObjList_FindNearestObjectByDefNo(obj, 0x814, &searchDist3);
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
        ref = ObjList_FindNearestObjectByDefNo(obj, 0x6cf, &searchDist);
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
LAB_8023ef14:
    return;
}
