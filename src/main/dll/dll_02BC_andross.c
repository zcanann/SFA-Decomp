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
#include "main/dll/dll_02BC_andross_constants.h"
#include "main/dll/dll_02BB_gflevelcon.h"
#include "main/dll/dll_02BD_androsshand.h"
#include "main/model.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"









#define GAMEBIT_ANDROSS_HIT_CUE_BASE 0x108 /* six consecutive random-hit cue bits */

#define ANDROSS_CHILD_OBJ_SPAWNED 0x819 /* cached into state->spawnedObj w/ spawnedObjLifetime */

#define ANDROSS_CHILD_OBJ_PROJECTILE_SPREAD 0x80d
#define ANDROSS_CHILD_OBJ_PROJECTILE_AIMED  0x7e4
#define ANDROSS_CHILD_OBJ_PROJECTILE_RING   0x859
#define ANDROSS_CHILD_OBJ_MARKER_ATTACH     0x608

#define ANDROSS_MAP_SHRINE 0xb /* Krazoa shrine map warped to on fight completion */

typedef struct AndrossRenderOp
{
    u8 unk00[0x43];
    s8 alpha;
} AndrossRenderOp;

STATIC_ASSERT(sizeof(AndrossRenderOp) == 0x44);

typedef struct AndrossChildSetup
{
    ObjPlacement base;
    u8 unk18[8];
    s16 flags;
} AndrossChildSetup;

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
extern u32 gAndrossDistortFilterParam;
extern void turnOnDistortionFilter(f32* pos, f32 a, u32* color, f32 c);

void fn_80239DD8(GameObject* obj, int state)
{
    f32 maxDist;
    char* nearObj;
    int newObj;

    maxDist = gAndrossSearchDistance;
    if (Obj_IsLoadingLocked())
    {
        nearObj = (char*)ObjList_FindNearestObjectByDefNo(obj, 0x7e5, &maxDist);
        if (nearObj != NULL)
        {
            newObj = Obj_AllocObjectSetup(0x24, ANDROSS_CHILD_OBJ_MARKER_ATTACH);
            ((ObjPlacement*)newObj)->posX = ((GameObject*)nearObj)->anim.localPosX;
            ((ObjPlacement*)newObj)->posY = ((GameObject*)nearObj)->anim.localPosY;
            ((ObjPlacement*)newObj)->posZ = ((GameObject*)nearObj)->anim.localPosZ;
            ((ObjPlacement*)newObj)->color[0] = 1;
            ((ObjPlacement*)newObj)->color[1] = 1;
            *(int*)(state + 0x10) = ((int (*)(int, int))loadObjectAtObject)((int)obj, newObj);
            if (*(void**)(state + 0x10) != NULL)
            {
                ((GameObject*)*(int*)(state + 0x10))->anim.alpha = 0xff;
                *(u8*)(*(int*)(state + 0x10) + 0x37) = 0xff;
                *(int*)(state + 0x90) = 0x12c;
            }
        }
    }
}

void fn_80239EAC(int obj, int state)
{
    f32 dx, dy, dz;
    int* objs;
    int cur;
    int i;
    int count;
    int defNo;

    {
        int* objList = ObjGroup_GetObjects(2, &count);
        for (i = 0, objs = objList; i < count; i++)
        {
            cur = *objs;
            defNo = *(s16*)(*(int*)&((GameObject*)cur)->anim.placementData);
            if (defNo == ANDROSS_CHILD_OBJ_PROJECTILE_SPREAD || defNo == ANDROSS_CHILD_OBJ_PROJECTILE_RING)
            {
                dy = *(f32*)(state + 0xc4) - ((GameObject*)cur)->anim.localPosY;
                dz = *(f32*)(state + 0xc8) - ((GameObject*)cur)->anim.localPosZ;
                dx = *(f32*)(state + 0xc0) - ((GameObject*)cur)->anim.localPosX;
                ((GameObject*)cur)->anim.rotX = getAngle(dx, dz);
                ((GameObject*)cur)->anim.rotY = -(s16)getAngle(dy, dz);
                arwprojectile_placeForward((GameObject*)(cur), (f32)(int)lbl_803DC4E8);
            }
            objs++;
        }
    }
}

void fn_80239FCC(int obj, int state)
{
    f32 ang;
    int rndDur;
    int newObj;
    int proj;
    int yaw;
    s16 rndYaw;

    if (Obj_IsLoadingLocked())
    {
        yaw = gGfLevelConProjectileYaw;
        lbl_803DDDC0 = lbl_803DDDC6;
        rndYaw = randomGetRange(-0x8000, 0x7fff);
        rndDur = randomGetRange(0x64, 0x12c);
        newObj = Obj_AllocObjectSetup(0x20, ANDROSS_CHILD_OBJ_PROJECTILE_RING);
        ang = gAndrossPi * (f32)(int)rndYaw / gAndrossHalfTurn;
        ((ObjPlacement*)newObj)->posX = (f32)(int)rndDur * mathSinf(ang) + *(f32*)(*(int*)state + 0xc);
        ((ObjPlacement*)newObj)->posY = (f32)(int)rndDur * mathCosf(ang) + *(f32*)(*(int*)state + 0x10);
        ((ObjPlacement*)newObj)->posZ = *(f32*)(state + 0xc8) - gAndrossProjectileBackOffset;
        ((GfProjectileSetup*)newObj)->yawHi = (*(s16*)obj + yaw) >> 8;
        ((GfProjectileSetup*)newObj)->pitch = lbl_803DDDC0;
        ((GfProjectileSetup*)newObj)->roll = 0;
        ((ObjPlacement*)newObj)->color[0] = 1;
        ((ObjPlacement*)newObj)->color[1] = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        if ((u32)proj != 0)
        {
            ((GameObject*)proj)->anim.rootMotionScale = lbl_803DC4E4;
            arwprojectile_setLifetime((GameObject*)(proj), lbl_803DC4E0);
            arwprojectile_placeForward((GameObject*)(proj), gAndrossProjectileSpeed);
        }
    }
}

void fn_8023A168(int obj, int state)
{
    int proj;
    int yawRnd;
    int pitchRnd;
    int newObj;

    if (Obj_IsLoadingLocked())
    {
        yawRnd = (s16)(randomGetRange(-0x1f40, 0x1f40) - 0x8000);
        pitchRnd = randomGetRange(-0x1f40, 0x1f40) >> 8;
        newObj = Obj_AllocObjectSetup(0x20, ANDROSS_CHILD_OBJ_PROJECTILE_SPREAD);
        ((ObjPlacement*)newObj)->posX = *(f32*)(state + 0xc0);
        ((ObjPlacement*)newObj)->posY = *(f32*)(state + 0xc4);
        ((ObjPlacement*)newObj)->posZ = *(f32*)(state + 0xc8);
        ((GfProjectileSetup*)newObj)->yawHi = (*(s16*)obj + yawRnd) >> 8;
        ((GfProjectileSetup*)newObj)->pitch = pitchRnd;
        ((GfProjectileSetup*)newObj)->roll = 0;
        ((ObjPlacement*)newObj)->color[0] = 1;
        ((ObjPlacement*)newObj)->color[1] = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        if ((void*)proj != NULL)
        {
            ((GameObject*)proj)->anim.rootMotionScale = gAndrossProjectileScale;
            arwprojectile_setLifetime((GameObject*)(proj), 0x6e);
            arwprojectile_placeForward((GameObject*)(proj), gAndrossProjectileSpeed);
        }
    }
}

void fn_8023A268(int obj, int state, int p3)
{
    f32 dx, dz, dist;
    int yaw;
    int newObj;

    if (Obj_IsLoadingLocked())
    {
        dx = *(f32*)(state + 0xc0) - *(f32*)(*(int*)state + 0xc);
        dz = *(f32*)(state + 0xc8) - *(f32*)(*(int*)state + 0x14);
        dist = sqrtf(dx * dx + dz * dz);
        yaw = (u16)getAngle(dx, dz);
        gGfLevelConProjectilePitch = (u16)getAngle(*(f32*)(state + 0xc4) - *(f32*)(*(int*)state + 0x10), dist) >> 8;
        newObj = Obj_AllocObjectSetup(0x20, ANDROSS_CHILD_OBJ_PROJECTILE_AIMED);
        ((ObjPlacement*)newObj)->posX = *(f32*)(state + 0xc0);
        ((ObjPlacement*)newObj)->posY = *(f32*)(state + 0xc4);
        ((ObjPlacement*)newObj)->posZ = *(f32*)(state + 0xc8);
        ((GfProjectileSetup*)newObj)->yawHi = (*(s16*)obj + yaw) >> 8;
        ((GfProjectileSetup*)newObj)->pitch = gGfLevelConProjectilePitch;
        ((GfProjectileSetup*)newObj)->roll = 0;
        ((ObjPlacement*)newObj)->color[0] = 1;
        ((ObjPlacement*)newObj)->color[1] = 1;
        obj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        if ((void*)obj != NULL)
        {
            arwprojectile_setLifetime((GameObject*)(obj), lbl_803DC4DC);
            arwprojectile_placeForward((GameObject*)(obj), (f32)(int)lbl_803DC4D8);
        }
    }
}

void fn_8023A3E4(int objArg, int hitState)
{
    u8 i;
    u32 hitVol;
    int hitType;
    int hitObj;
    int got;
    u8* s;
    int obj;
    u8 adjusted;
    int texIdx;
    u8 state;
    ObjTextureRuntimeSlot* tex;

    obj = objArg;
    s = (u8*)hitState;
    got = ObjHits_GetPriorityHit((GameObject*)(objArg), &hitObj, &hitType, &hitVol);
    {
        u8 j;
        int off;
        for (j = 0; j < 4; j++)
        {
            int v = s[off = j + 178] - framesThisStep;
            if (v < 0)
                v = 0;
            s[off] = v;
        }
    }
    if (got != 0)
    {
        int ht = hitType;
        switch (ht)
        {
        case 0:
        case 1:
        case 2:
        {
            u8* hp = s + ht;
            if (hp[0xAE] != 0 && hp[0xB2] == 0)
            {
                hp[0xAE] -= 1;
                (s + hitType)[0xB2] = 6;
                if ((s + hitType)[0xAE] != 0)
                    Sfx_PlayFromObject(obj, SFXTRIG_wmap_nameoff);
                else
                    Sfx_PlayFromObject(obj, SFXTRIG_en_barrelblow11);
                switch (hitType)
                {
                case 0:
                    ((GfHitState*)s)->pitchVel = -0xfa;
                    break;
                case 1:
                    ((GfHitState*)s)->pitchVel = 0xfa;
                    break;
                case 2:
                    ((GfHitState*)s)->rollVel = -0xc8;
                    break;
                }
            }
            break;
        }
        case 3:
        {
            if (((GameObject*)hitObj)->anim.seqId == 0x605)
            {
                u8* hp = s + ht;
                if (hp[0xB2] == 0 && hp[0xAE] != 0 && ((GfHitState*)s)->mode == 0xc)
                {
                    Obj_SetModelColorFadeRecursive(obj, 0x19, 0xc8, 0, 0, 1);
                    (s + hitType)[0xAE] -= 1;
                    (s + hitType)[0xB2] = 0xc8;
                }
            }
            break;
        }
        }
    }
    for (i = 0; i < 3; i++)
    {
        int idx = i;
        u8* p = s + idx;
        if (p[0xAE] != 0)
        {
            if (p[0xB2] != 0)
                p[0xB9] = 1;
            else
                p[0xB9] = 0;
        }
        else
        {
            p[0xB9] = 2;
        }
        state = p[0xB9];
        adjusted = state;
        texIdx = lbl_803DC4C8[idx];
        if ((u32)texIdx < 2 && state == 1)
            adjusted = 0;
        tex = objFindTexture((GameObject*)obj, texIdx * 2, 0);
        tex->textureId = adjusted << 8;
        if ((u32)texIdx == 2 && state == 1)
            state = 0;
        tex = objFindTexture((GameObject*)obj, texIdx * 2 + 1, 0);
        tex->textureId = state << 8;
    }
}




void andross_setPartSignal(GameObject* obj, u8 signal)
{
    int state;

    if ((void*)obj == NULL)
    {
        return;
    }
    state = *(int*)&(obj)->extra;
    ((AndrossState*)state)->signalFlags |= signal;
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
    ang = gAndrossPi * yaw / gAndrossHalfTurn;
    state->velX = mag * mathSinf(ang);
    state->velY = mag * mathCosf(ang);
    arwarwing_getVelocity((int)vel, (int)state->arwingObj);
    state->velX -= vel[0] * gAndrossArwingVelDamp;
    state->velY -= vel[1] * gAndrossArwingVelDamp;
    state->velZ = zVel;
    return result;
}
void fn_8023A87C(GameObject* obj, int state)
{
    void* spawned;

    spawned = *(void**)&((AndrossState*)state)->effectHandle;
    if (spawned != NULL)
    {
        ((GameObject*)spawned)->anim.localPosZ -= gAndrossThree;
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
        f32 zero = gAndrossZero;
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
int andross_SeqFn(GameObject* obj)
{
    int state = *(int*)&(obj)->extra;
    int i;
    f32 fade;
    f32 alpha;
    int model;
    int op;

    *(f32*)(state + 0x68) = gAndrossZero;
    fade = ((AndrossState*)state)->fadeAlpha;
    model = *(int*)Obj_GetActiveModel((int)obj);
    i = 0;
    alpha = gAndrossAlphaScale * fade;
    for (; i < *(u8*)(model + 0xf8); i++)
    {
        op = ObjModel_GetRenderOp(model, i);
        *(s8*)(op + 0x43) = alpha;
    }
    return 0;
}
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
void andross_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, gAndrossOne);
}
void andross_hitDetect(void)
{
}
void andross_update(int obj)
{
    GameObject* boss;
    u8 actionChanged;
    u8 phaseChanged;
    u8 spawnIndex;
    u8 pathIndex;
    u8 cueIndex;
    u8 delayIndex;
    int index;
    u8 signalReceived;
    AndrossState* state;
    AndrossState* signalState;
    AndrossHandState* handStateA;
    AndrossHandState* handStateB;
    GameObject* aimTarget;
    GameObject** spawnSlot;
    ModelFileHeader* model;
    AndrossRenderOp* renderOp;
    AndrossChildSetup* childSetup;
    int rotationDelta;
    s16 durationBeforeStep;
    u32 val;
    f32 fc;
    f32 fval;
    s16 sval;
    int found;
    s8 bval;
    s16 randVal;
    int objId;
    f32 fa;
    f32 fb;
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
    state = boss->extra;
    phaseChanged = 0;
    actionChanged = 0;
    pathIndex = 0;
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
    for (spawnIndex = 0; spawnIndex < 4; spawnIndex++)
    {
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
        phaseChanged = 1;
    }
    state->prevFightPhase = found;
    fval = gAndrossZero;
    state->velX = gAndrossZero;
    state->velY = fval;
    state->velZ = fval;
    if (-0x4000 < state->targetRotX && boss->anim.rotX < 0x4000)
    {
        pathIndex = 1;
    }
    ObjPath_GetPointWorldPosition(
        obj, pathIndex, &state->cachedPosX, &state->cachedPosY, &state->cachedPosZ, 0);
    if (pathIndex == 1)
    {
        fa = state->cachedPosY;
        fval = gAndrossPathOffset;
        state->cachedPosY = fa + fval;
        state->cachedPosZ += fval;
    }
    switch (state->fightPhase)
    {
    case 1:
        if (phaseChanged)
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
        if (phaseChanged)
        {
            state->signalFlags &= ~0x6;
            if (state->actionState == 0x16)
            {
                androsshand_setState(state->handObjA, 1, 1);
                androsshand_setState(state->handObjB, 1, 1);
            }
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
        if (phaseChanged)
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
        if (phaseChanged)
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
        if (phaseChanged)
        {
            state->actionState = 0x1c;
            state->actionToggle = 0;
        }
        break;
    }
    found = state->actionState;
    if (found != state->prevActionState)
    {
        actionChanged = 1;
    }
    state->prevActionState = found;
    switch (state->actionState)
    {
    case 0:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[0];
            }
            if (state->fightPhase == 1)
            {
                state->durationTimer = gAndrossLongDuration;
            }
            else
            {
                state->durationTimer = gAndrossShortDuration;
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < gAndrossNarrowMin) ? gAndrossNarrowMin : ((fa > gAndrossNarrowMax) ? gAndrossNarrowMax : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
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
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0xc, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[12];
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < gAndrossNarrowMin) ? gAndrossNarrowMin : ((fa > gAndrossNarrowMax) ? gAndrossNarrowMax : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= gAndrossOne)
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
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0xe, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[14];
            }
            state->durationTimer = gAndrossWideMax;
            state->actionTimer = 0xffff;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < gAndrossNarrowMin) ? gAndrossNarrowMin : ((fa > gAndrossNarrowMax) ? gAndrossNarrowMax : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_roar1);
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0)
        {
            fn_8023A268(obj, (int)state, 0);
            state->actionTimer = lbl_803DC43C;
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
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
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0xd, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[13];
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < gAndrossVerticalMin) ? gAndrossVerticalMin : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= gAndrossOne)
        {
            state->actionPending = 1;
        }
        break;
    case 4:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[0];
            }
            mainSetBits(0xd, 1);
            state->durationTimer = gAndrossVerticalMax;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < gAndrossVerticalMin) ? gAndrossVerticalMin : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
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
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[0];
            }
            mainSetBits(0xd, 1);
            state->durationTimer = gAndrossVerticalMax;
        }
        for (cueIndex = 0; cueIndex < 6; cueIndex++)
        {
            if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
            {
                state->timer = 0x3c;
                break;
            }
        }
        if (cueIndex >= 6)
        {
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < gAndrossVerticalMin) ? gAndrossVerticalMin : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
        {
            state->actionPending = 1;
            mainSetBits(0xd, 0);
        }
        break;
    case 6:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[0];
            }
            androsshand_setState(state->handObjB, 4, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossHorizontalMin) ? gAndrossHorizontalMin : ((fb > gAndrossHorizontalMax) ? gAndrossHorizontalMax : fb);
        fb = (fa < gAndrossNarrowMin) ? gAndrossNarrowMin : ((fa > gAndrossNarrowMax) ? gAndrossNarrowMax : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX = (gAndrossShortDuration * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        signalReceived = 0;
        signalState = boss->extra;
        if ((signalState->signalFlags & 1) != 0)
        {
            signalState->signalFlags &= ~1;
            signalReceived = 1;
        }
        if (signalReceived)
        {
            state->actionPending = 1;
        }
        break;
    case 7:
        if (actionChanged)
        {
            androsshand_setState(state->handObjA, 4, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossHorizontalMin) ? gAndrossHorizontalMin : ((fb > gAndrossHorizontalMax) ? gAndrossHorizontalMax : fb);
        fb = (fa < gAndrossNarrowMin) ? gAndrossNarrowMin : ((fa > gAndrossNarrowMax) ? gAndrossNarrowMax : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX = (gAndrossShortDuration * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        signalReceived = 0;
        signalState = boss->extra;
        if ((signalState->signalFlags & 1) != 0)
        {
            signalState->signalFlags &= ~1;
            signalReceived = 1;
        }
        if (signalReceived)
        {
            state->actionPending = 1;
        }
        break;
    case 9:
        if (actionChanged)
        {
            androsshand_setState(state->handObjA, 6, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < gAndrossVerticalMin) ? gAndrossVerticalMin : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        signalReceived = 0;
        signalState = boss->extra;
        if ((signalState->signalFlags & 1) != 0)
        {
            signalState->signalFlags &= ~1;
            signalReceived = 1;
        }
        if (signalReceived)
        {
            state->actionPending = 1;
        }
        break;
    case 8:
        if (actionChanged)
        {
            androsshand_setState(state->handObjB, 6, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < gAndrossVerticalMin) ? gAndrossVerticalMin : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        signalReceived = 0;
        signalState = boss->extra;
        if ((signalState->signalFlags & 1) != 0)
        {
            signalState->signalFlags &= ~1;
            signalReceived = 1;
        }
        if (signalReceived)
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
            fc = (fb < gAndrossHorizontalMin) ? gAndrossHorizontalMin : ((fb > gAndrossHorizontalMax) ? gAndrossHorizontalMax : fb);
            fb = (fa < gAndrossNarrowMin) ? gAndrossNarrowMin : ((fa > gAndrossNarrowMax) ? gAndrossNarrowMax : fa);
            fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
            state->targetPosX = (gAndrossShortDuration * fa + (state->homePosX + fc));
            fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
            state->targetPosY =
                (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
            state->targetPosZ = state->homePosZ;
            if (actionChanged)
            {
                androsshand_setState(state->handObjA, 5, 0);
                androsshand_setState(state->handObjB, 5, 0);
            }
            signalReceived = 0;
            signalState = boss->extra;
            if ((signalState->signalFlags & 1) != 0)
            {
                signalState->signalFlags &= ~1;
                signalReceived = 1;
            }
            if (signalReceived)
            {
                state->actionPending = 1;
            }
        }
        break;
    case 0xb:
    case 0xd:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 1, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[1];
            }
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
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    break;
                }
            }
            if (cueIndex >= 6)
            {
                state->timer -= framesThisStep;
                if (state->timer <= 0)
                {
                    mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                    state->timer = 0x3c;
                }
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossFineMin) ? gAndrossFineMin : ((fb > gAndrossSwayAmplitudeY) ? gAndrossSwayAmplitudeY : fb);
        fb = (fa < gAndrossNarrowMin) ? gAndrossNarrowMin : ((fa > gAndrossNarrowMax) ? gAndrossNarrowMax : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeY * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY = (gAndrossFineMax * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= gAndrossOne)
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
        fval = gAndrossHalf * boss->anim.currentMoveProgress;
        if (fval < gAndrossHalf)
        {
            fc = -(gAndrossTwo * (gAndrossFlightDistance * fval) - gAndrossFarDistance);
            if (fval < gAndrossCentistep)
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
        if (fval > gAndrossFullTurn)
        {
            gAndrossDistortPhase = fval - gAndrossFullTurn;
        }
        turnOnDistortionFilter(&state->cachedPosX, fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        break;
    case 0xe:
        fval = gAndrossHalf * boss->anim.currentMoveProgress + gAndrossHalf;
        if (fval < gAndrossHalf)
        {
            fc = -(gAndrossTwo * (gAndrossFlightDistance * fval) - gAndrossFarDistance);
            if (fval < gAndrossCentistep)
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
        if (fval > gAndrossFullTurn)
        {
            gAndrossDistortPhase = fval - gAndrossFullTurn;
        }
        turnOnDistortionFilter(&state->cachedPosX, fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 2, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[2];
            }
            state->unkB1[0] = 0;
            mainSetBits(0x10, 0);
            state->actionTimer = lbl_803DC44C;
            state->durationTimer = gAndrossZero;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < gAndrossHorizontalMin) ? gAndrossHorizontalMin : ((fa > gAndrossHorizontalMax) ? gAndrossHorizontalMax : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeY * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY = (gAndrossFineMax * fc + (state->homePosY + fb));
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
        if (state->durationTimer < gAndrossZero)
        {
            fn_80239FCC(obj, (int)state);
            state->durationTimer += lbl_803DC450;
        }
        fn_80239EAC(obj, (int)state);
        if (mainGetBit(0x10) != 0)
        {
            mainSetBits(0x10, 0);
            state->actionState = 0x1a;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossFullTurn)
            {
                gAndrossDistortPhase = fval - gAndrossFullTurn;
            }
            turnOnDistortionFilter(&state->cachedPosX, gAndrossFarDistance, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    case 0xc:
        fval = gAndrossHalf * boss->anim.currentMoveProgress + gAndrossHalf;
        if (fval < gAndrossHalf)
        {
            fc = -(gAndrossTwo * (gAndrossFlightDistance * fval) - gAndrossFarDistance);
            if (fval < gAndrossCentistep)
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
        if (fval > gAndrossFullTurn)
        {
            gAndrossDistortPhase = fval - gAndrossFullTurn;
        }
        turnOnDistortionFilter(&state->cachedPosX, fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 2, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[2];
            }
            if (state->fightPhase < 5)
            {
                state->unkB1[0] = 1;
            }
            state->actionTimer = lbl_803DC460;
            state->durationTimer = gAndrossZero;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_missileloop);
        if (state->fightPhase == 5)
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    break;
                }
            }
            if (cueIndex >= 6)
            {
                state->timer -= framesThisStep;
                if (state->timer <= 0)
                {
                    mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                    state->timer = 0x3c;
                }
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossNarrowMin) ? gAndrossNarrowMin : ((fb > gAndrossNarrowMax) ? gAndrossNarrowMax : fb);
        fb = (fa < gAndrossFineMin) ? gAndrossFineMin : ((fa > gAndrossSwayAmplitudeY) ? gAndrossSwayAmplitudeY : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeY * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY = (gAndrossFineMax * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        bval = fn_8023A6A4(state, lbl_803DC454, lbl_803DC458, lbl_803DC45C);
        if (bval != 0)
        {
            state->actionState = 0xf;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
            gAndrossDistortPhase = fval;
            if (fval > gAndrossFullTurn)
            {
                gAndrossDistortPhase = fval - gAndrossFullTurn;
            }
            turnOnDistortionFilter(&state->cachedPosX, gAndrossFarDistance, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
        {
            fn_80239FCC(obj, (int)state);
            state->durationTimer += lbl_803DC464;
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
            if (fval > gAndrossFullTurn)
            {
                gAndrossDistortPhase = fval - gAndrossFullTurn;
            }
            turnOnDistortionFilter(&state->cachedPosX, gAndrossFarDistance, &gAndrossDistortFilterParam,
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
                state->velZ = gAndrossZero;
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
                fval = gAndrossDistortPhase + gAndrossDistortPhaseStep;
                gAndrossDistortPhase = fval;
                if (fval > gAndrossFullTurn)
                {
                    gAndrossDistortPhase = fval - gAndrossFullTurn;
                }
                turnOnDistortionFilter(&state->cachedPosX, gAndrossFarDistance, &gAndrossDistortFilterParam,
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
            if (fval > gAndrossFullTurn)
            {
                gAndrossDistortPhase = fval - gAndrossFullTurn;
            }
            turnOnDistortionFilter(&state->cachedPosX, gAndrossFarDistance, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    case 0xf:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x10, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[16];
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossVerticalMin) ? gAndrossVerticalMin : ((fb > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fb);
        fb = (fa < gAndrossNarrowMin) ? gAndrossNarrowMin : ((fa > gAndrossNarrowMax) ? gAndrossNarrowMax : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX = (gAndrossShortDuration * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= gAndrossOne)
        {
            state->actionPending = 1;
        }
        break;
    case 0x10:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x10, gAndrossZero, 0);
                animState->animSpeed = gAndrossSlowAnimSpeed;
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = gAndrossZero;
        fc = (fb < fc) ? fc : ((fb > fc) ? fc : fb);
        fb = gAndrossZero;
        fb = (fa < fb) ? fb : ((fa > fb) ? fb : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX = (gAndrossZero * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY = (gAndrossZero * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        fc = state->cachedPosX - state->arwingObj->anim.localPosX;
        velCalc3.x = fc * lbl_803DC468;
        fc = state->cachedPosY - state->arwingObj->anim.localPosY;
        velCalc3.y = fc * lbl_803DC468;
        fc = state->cachedPosZ - state->arwingObj->anim.localPosZ;
        velCalc3.z = fc * lbl_803DC468;
        velArg3 = velCalc3;
        arwarwing_setVelocity((int)state->arwingObj, (int)&velArg3);
        fval = (gAndrossWideMin > -(gAndrossProjectileScale * timeDelta - state->camOffsetAccum))
                   ? gAndrossWideMin
                   : -(gAndrossProjectileScale * timeDelta - state->camOffsetAccum);
        state->camOffsetAccum = fval;
        if (boss->anim.currentMoveProgress >= gAndrossOne)
        {
            state->arwingObj->anim.flags |= 0x4000;
            state->actionState = 0x11;
        }
        break;
    case 0x11:
        if (actionChanged)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_and_falcoflyby);
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x15, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[21];
            }
            arwarwing_addHealth((int)state->arwingObj, 0xfffffffc);
        }
        fval = (gAndrossWideMin > -(gAndrossProjectileScale * timeDelta - state->camOffsetAccum))
                   ? gAndrossWideMin
                   : -(gAndrossProjectileScale * timeDelta - state->camOffsetAccum);
        state->camOffsetAccum = fval;
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = gAndrossZero;
        fc = (fb < fc) ? fc : ((fb > fc) ? fc : fb);
        fb = gAndrossZero;
        fb = (fa < fb) ? fb : ((fa > fb) ? fb : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX = (gAndrossZero * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY = (gAndrossZero * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= gAndrossOne)
        {
            state->actionPending = 1;
        }
        break;
    case 0x12:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x12, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[18];
            }
            androsshand_setState(state->handObjA, 0, 0);
            androsshand_setState(state->handObjB, 0, 0);
            if ((state->fightPhase == 5) && (state->actionToggle != 0))
            {
                mainSetBits(0xe, 1);
            }
        }
        state->fadeAlpha -= gAndrossFadeStep;
        fval = (gAndrossZero > state->fadeAlpha) ? gAndrossZero : state->fadeAlpha;
        state->fadeAlpha = fval;
        fc = state->fadeAlpha;
        model = *(ModelFileHeader**)Obj_GetActiveModel(obj);
        for (index = 0, fval = gAndrossAlphaScale * fc;
             index < model->renderOpCount; index++)
        {
            renderOp = (AndrossRenderOp*)ObjModel_GetRenderOp((int)model, index);
            renderOp->alpha = fval;
        }
        if ((state->fightPhase == 5) && (state->actionToggle == 0))
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    break;
                }
            }
            if (cueIndex >= 6)
            {
                state->timer -= framesThisStep;
                if (state->timer <= 0)
                {
                    mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                    state->timer = 0x3c;
                }
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < gAndrossNarrowMin) ? gAndrossNarrowMin : ((fa > gAndrossNarrowMax) ? gAndrossNarrowMax : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX = (gAndrossShortDuration * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= gAndrossOne)
        {
            state->actionState = 0x13;
        }
        break;
    case 0x13:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x13, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[19];
            }
            if (state->fightPhase == 5)
            {
                state->durationTimer = gAndrossProjectileBackOffset;
            }
            else
            {
                state->durationTimer = gAndrossWideMax;
            }
            state->actionTimer = 0xffff;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_spitout);
        if ((state->fightPhase == 5) && (state->actionToggle == 0))
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    break;
                }
            }
            if (cueIndex >= 6)
            {
                state->timer -= framesThisStep;
                if (state->timer <= 0)
                {
                    mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                    state->timer = 0x3c;
                }
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossFadeRangeMin) ? gAndrossFadeRangeMin : ((fb > gAndrossProjectileBackOffset) ? gAndrossProjectileBackOffset : fb);
        fb = (fa < gAndrossFadeRangeYMin) ? gAndrossFadeRangeYMin : ((fa > gAndrossFadeRangeYMax) ? gAndrossFadeRangeYMax : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX = (gAndrossShortDuration * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->actionTimer -= framesThisStep;
        durationBeforeStep = state->durationTimer;
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
        for (delayIndex = 0; delayIndex < 2; delayIndex++)
        {
            if ((((state->spawnedObj == NULL) &&
                  (state->actionTimer <= delayPair[delayIndex])) &&
                 (durationBeforeStep > delayPair[delayIndex])) &&
                (Obj_IsLoadingLocked() != 0))
            {
                childSetup = (AndrossChildSetup*)Obj_AllocObjectSetup(
                    sizeof(AndrossChildSetup), ANDROSS_CHILD_OBJ_SPAWNED);
                childSetup->base.posX = state->cachedPosX;
                childSetup->base.posY = state->cachedPosY;
                childSetup->base.posZ = state->cachedPosZ;
                childSetup->base.color[0] = 1;
                childSetup->base.color[1] = 1;
                childSetup->flags = -1;
                state->spawnedObj = (GameObject*)((int (*)(int, int))loadObjectAtObject)(
                    obj, (int)childSetup);
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
        if (state->durationTimer < gAndrossZero)
        {
            state->actionState = 0x14;
        }
        break;
    case 0x14:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x14, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[20];
            }
        }
        if ((state->fightPhase == 5) && (state->actionToggle == 0))
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    break;
                }
            }
            if (cueIndex >= 6)
            {
                state->timer -= framesThisStep;
                if (state->timer <= 0)
                {
                    mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                    state->timer = 0x3c;
                }
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < gAndrossWideMin) ? gAndrossWideMin : ((fb > gAndrossWideMax) ? gAndrossWideMax : fb);
        fb = (fa < -gAndrossShortDuration) ? -gAndrossShortDuration : ((fa > gAndrossShortDuration) ? gAndrossShortDuration : fa);
        fa = mathSinf(((gAndrossPi * gAndrossSwayPhaseX) / gAndrossHalfTurn));
        state->targetPosX =
            (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((gAndrossPi * gAndrossSwayPhaseY) / gAndrossHalfTurn));
        state->targetPosY =
            (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= gAndrossOne)
        {
            state->actionPending = 1;
        }
        break;
    case 0x19:
    case 0x1a:
        if (actionChanged)
        {
            Sfx_PlayFromObject(obj, SFXTRIG__UNK_832);
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 4, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[4];
            }
        }
        if (boss->anim.currentMoveProgress >= gAndrossOne)
        {
            state->actionPending = 1;
        }
        break;
    case 0x1b:
        if (actionChanged)
        {
            mainSetBits(0x10, 0);
            state->actionTimer = 0x1e;
            arwarwing_resetFlightState(state->arwingObj);
            state->arwingObj->anim.localPosZ = state->savedPosZ;
            state->camOffsetAccum = gAndrossZero;
        }
        state->targetPosX = state->homePosX;
        state->targetPosY = state->homePosY;
        state->targetPosZ = state->homePosZ;
        if ((mainGetBit(0x10) != 0) && (state->actionTimer-- == 0))
        {
            mainSetBits(0x10, 0);
            state->actionPending = 1;
        }
        break;
    case 0x1c:
        if (actionChanged)
        {
            androssbrain_setState(state->lightAnchorObj, 1, 0);
            ObjHits_DisableObject(obj);
            state->actionTimer = 0x3c;
            state->durationTimer = gAndrossThree;
            state->targetPosX = state->homePosX;
            state->targetPosY = state->homePosY;
            state->targetPosZ = state->homePosZ;
            fval = gAndrossZero;
            boss->anim.velocityX = gAndrossZero;
            boss->anim.velocityY = fval;
            boss->anim.velocityZ = fval;
            state->springStiffness = gAndrossCentistep;
            state->springDamping = gAndrossSpringDamping;
        }
        state->fadeAlpha += gAndrossFadeStep;
        fval = (gAndrossMaxFadeAlpha < state->fadeAlpha) ? gAndrossMaxFadeAlpha
                                                                          : state->fadeAlpha;
        state->fadeAlpha = fval;
        for (cueIndex = 0; cueIndex < 6; cueIndex++)
        {
            if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
            {
                state->timer = 0x3c;
                break;
            }
        }
        if (cueIndex >= 6)
        {
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        }
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0)
        {
            state->durationTimer -= gAndrossOne;
            if (state->durationTimer < gAndrossZero)
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
        model = *(ModelFileHeader**)Obj_GetActiveModel(obj);
        for (index = 0, fval = gAndrossAlphaScale * fc;
             index < model->renderOpCount; index++)
        {
            renderOp = (AndrossRenderOp*)ObjModel_GetRenderOp((int)model, index);
            renderOp->alpha = fval;
        }
        break;
    case 0x1d:
        if (actionChanged)
        {
            androssbrain_setState(state->lightAnchorObj, 1, 0);
            ObjHits_DisableObject(obj);
            state->actionTimer = lbl_803DC484;
            state->targetPosX = state->arwingObj->anim.localPosX;
            state->targetPosY = state->arwingObj->anim.localPosY + gAndrossSpawnOffsetY;
            state->targetPosZ = state->arwingObj->anim.localPosZ + gAndrossSpawnOffsetZ;
            fval = gAndrossZero;
            boss->anim.velocityX = gAndrossZero;
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
        if (actionChanged)
        {
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[0];
            }
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
            fval = (gAndrossCameraMin > -(gAndrossCameraRate * timeDelta - state->camOffsetAccum))
                       ? gAndrossCameraMin
                       : -(gAndrossCameraRate * timeDelta - state->camOffsetAccum);
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
        rotationDelta = sval;
        if (rotationDelta < 0)
        {
            rotationDelta = -rotationDelta;
        }
        if (rotationDelta < 2000)
        {
            handStateA = state->handObjA->extra;
            handStateB = state->handObjB->extra;
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
        handStateA = state->handObjA->extra;
        handStateB = state->handObjB->extra;
        if (actionChanged)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_drak_roar1);
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x16, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[22];
            }
            state->laughPlayed = 0;
            state->ringPlayed = 0;
        }
        fc = boss->anim.currentMoveProgress;
        if (fc < gAndrossMoveSplit)
        {
            fc = mathSinf(
                ((gAndrossPi * (float)(gAndrossAngleScale * (gAndrossMoveQuarter * (fc / gAndrossMoveSplit)))) / gAndrossHalfTurn));
            state->targetPosZ = (gAndrossProjectileBackOffset * fc + state->homePosZ);
        }
        else
        {
            fc = mathSinf(((gAndrossPi * (float)(gAndrossAngleScale * (gAndrossMoveThreeQuarters * ((fc - gAndrossMoveSplit) / gAndrossMoveTailScale) +
                                                                   gAndrossMoveQuarter))) /
                           gAndrossHalfTurn));
            state->targetPosZ = lbl_803DC48C * fc + state->homePosZ;
        }
        if ((boss->anim.currentMoveProgress > gAndrossMoveHalf) &&
            (state->ringPlayed == 0))
        {
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
            state->ringPlayed = 1;
        }
        if ((boss->anim.currentMoveProgress > gAndrossMoveSoundPoint) &&
            (state->laughPlayed == 0))
        {
            Sfx_PlayFromObject(obj, SFXTRIG_and_laugh);
            state->laughPlayed = 1;
        }
        bval = handStateA->handState;
        if ((((bval != 2) && (bval != 1)) &&
             (bval = handStateB->handState, bval != 2)) &&
            (bval != 1))
        {
            if (boss->anim.currentMoveProgress >= gAndrossOne)
            {
                state->actionPending = 1;
            }
            else if (boss->anim.currentMoveProgress > gAndrossMoveHalf)
            {
                state->targetRotX = 0;
                androsshand_setState(state->handObjA, 1, (state->fightPhase == 4) + 1);
                androsshand_setState(state->handObjB, 1, (state->fightPhase == 4) + 1);
                state->signalFlags &= ~0x6;
            }
        }
        break;
    case 0x17:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 3, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[3];
            }
            state->soundTimer = gAndrossZero;
            state->roarPlayed = 0;
        }
        state->soundTimer += timeDelta;
        if ((state->soundTimer > gAndrossSoundDelay) &&
            (state->roarPlayed == 0))
        {
            Sfx_PlayFromObject(obj, SFXTRIG_drak_pain1);
            state->roarPlayed = 1;
        }
        if (boss->anim.currentMoveProgress <= lbl_803DC490)
        {
            state->cachedPosX = boss->anim.localPosX;
            state->cachedPosY = boss->anim.localPosY - gAndrossArwingOffsetY;
            state->cachedPosZ = boss->anim.localPosZ - gAndrossArwingOffsetZ;
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
            fval = (gAndrossZero < gAndrossCameraRate * timeDelta + state->camOffsetAccum)
                       ? gAndrossZero
                       : gAndrossCameraRate * timeDelta + state->camOffsetAccum;
            state->camOffsetAccum = fval;
            state->arwingFlightActive = 0;
            state->arwingObj->anim.flags &= ~0x4000;
            rotationDelta = (int)((f32)(s16)arwarwing_getRotY((int)state->arwingObj) + fc * lbl_803DC49C);
            arwarwing_setRotY((int)state->arwingObj, rotationDelta);
            thrustB.x = gAndrossZero;
            thrustB.y = gAndrossZero;
            thrustB.z = fc * lbl_803DC498;
            thrustBArg = thrustB;
            arwarwing_setVelocity((int)state->arwingObj, (int)&thrustBArg);
        }
        if (boss->anim.currentMoveProgress >= gAndrossOne)
        {
            state->actionPending = 1;
        }
        break;
    case 0x18:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x11, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[17];
            }
            state->roarPlayed = 0;
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
            fval = (gAndrossZero < gAndrossFineMax * timeDelta + state->camOffsetAccum)
                       ? gAndrossZero
                       : gAndrossFineMax * timeDelta + state->camOffsetAccum;
            state->camOffsetAccum = fval;
            state->arwingFlightActive = 0;
            state->arwingObj->anim.flags &= ~0x4000;
            rotationDelta = (int)((f32)(s16)arwarwing_getRotY((int)state->arwingObj) + fc * lbl_803DC4AC);
            arwarwing_setRotY((int)state->arwingObj, rotationDelta);
            thrustA.x = gAndrossZero;
            thrustA.y = gAndrossZero;
            thrustA.z = fc * lbl_803DC4A8;
            thrustAArg = thrustA;
            arwarwing_setVelocity((int)state->arwingObj, (int)&thrustAArg);
            if (state->roarPlayed == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_drak_pain1);
                state->roarPlayed = 1;
            }
        }
        if (boss->anim.currentMoveProgress >= gAndrossOne)
        {
            state->actionPending = 1;
        }
        break;
    case 0x1e:
        if ((mainGetBit(2) != 0) || (mainGetBit(3) != 0) ||
            (mainGetBit(4) != 0))
        {
            mainSetBits(GAMEBIT_WM_ObjGroups, 0);
            (*gMapEventInterface)->setMapAct(ANDROSS_MAP_SHRINE, 7);
            unlockLevel(0, 0, 1);
            loadMapAndParent(mapGetDirIdx(ANDROSS_MAP_SHRINE));
            objId = mapGetDirIdx(ANDROSS_MAP_SHRINE);
            lockLevel(objId, 1);
            warpToMap(0x4e, 0);
            state->fadeAlpha = gAndrossZero;
            state->actionState = 0x1f;
        }
        break;
    case 0x1f:
        break;
    }
    camActionParam = -gAndrossLongDuration + state->camOffsetAccum;
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
    if (gAndrossZero == state->velZ)
    {
        if (state->arwingFlightActive != 0)
        {
            fn_8023A6A4(state, lbl_803DC4B4, lbl_803DC4B8, gAndrossZero);
        }
        else
        {
            state->velZ =
                lbl_803DC4B0 * (state->savedPosZ - state->arwingObj->anim.localPosZ);
        }
    }
    if (state->arwingObj->pendingParentObj == NULL)
    {
        velAdd = state->velocity;
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
    state->rotXSpeed += (sval / lbl_803DC430 - state->rotXSpeed) / lbl_803DC434;
    state->rotYSpeed += (-boss->anim.rotY / lbl_803DC430 - state->rotYSpeed) /
                        lbl_803DC434;
    boss->anim.rotX += state->rotXSpeed;
    boss->anim.rotY += state->rotYSpeed;
    ObjAnim_AdvanceCurrentMove((int)obj, state->animSpeed, timeDelta, 0);
    fn_8023A3E4(obj, (int)state);
    fn_8023A87C(boss, (int)state);
    if (state->spawnedObj != NULL)
    {
        state->spawnedObj->anim.localPosZ -= gAndrossThree;
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
        searchDist0 = gAndrossSearchDistance;
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
        searchDist1 = gAndrossSearchDistance;
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
        searchDist2 = gAndrossSearchDistance;
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
        searchDist3 = gAndrossSearchDistance;
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
        searchDist = gAndrossSearchDistance;
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
    ((AndrossState*)state)->camOffsetAccum = gAndrossZero;
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

int lbl_803DC430 = 20;
int lbl_803DC434 = 10;
int gAndrossFlightHalfWidth = 600;
int lbl_803DC43C = 2;
f32 lbl_803DC440 = 3.0f;
f32 lbl_803DC444 = 5.0f;
f32 lbl_803DC448 = 0.02f;
int lbl_803DC44C = 200;
int lbl_803DC450 = 10;
f32 lbl_803DC454 = 2.0f;
f32 lbl_803DC458 = 120.0f;
f32 lbl_803DC45C = 0.03f;
int lbl_803DC460 = 600;
int lbl_803DC464 = 10;
f32 lbl_803DC468 = 0.1f;
int lbl_803DC46C = 2;
f32 gAndrossSpawnRandX = 300.0f;
f32 gAndrossSpawnRandY = 200.0f;
f32 gAndrossSpawnRandZ = 50.0f;
f32 gAndrossSpawnOffsetY = -100.0f;
f32 gAndrossSpawnOffsetZ = 280.0f;
int lbl_803DC484 = 40;
f32 lbl_803DC488 = 0.01f;
int lbl_803DC48C = 300;
f32 lbl_803DC490 = 0.38f;
f32 lbl_803DC494 = 0.07f;
f32 lbl_803DC498 = 0.05f;
f32 lbl_803DC49C = 10.0f;
f32 lbl_803DC4A0 = 0.38f;
f32 lbl_803DC4A4 = 0.04f;
f32 lbl_803DC4A8 = 0.05f;
f32 lbl_803DC4AC = 10.0f;
f32 lbl_803DC4B0 = 0.0005f;
f32 lbl_803DC4B4 = 2.0f;
f32 lbl_803DC4B8 = 100.0f;
s16 gAndrossSwayPhaseStepX = 150;
s16 gAndrossSwayPhaseStepY = 280;
f32 lbl_803DC4C0 = 50.0f;
f32 gAndrossArwingVelDamp = 0.2f;
u8 lbl_803DC4C8[4] = {1, 0, 2, 0};
u32 gAndrossDistortFilterParam = 0x0000ff00;
f32 gAndrossDistortPhaseStep = 0.006f;
f32 gAndrossDistortPhaseReset = 3.142f;
int lbl_803DC4D8 = 10;
int lbl_803DC4DC = 90;
int lbl_803DC4E0 = 110;
f32 lbl_803DC4E4 = 5.0f;
int lbl_803DC4E8 = 7;
int lbl_803DC4EC = 200;
