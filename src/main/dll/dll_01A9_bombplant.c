/* DLL 0x01A9 — bombplant / enemymushroom group. TU: 0x801D286C–0x801D2C54. */
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/ediblemushroom.h"
#include "main/dll/bombplant_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/SH/dll_01A9_bombplant.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/dll_01A9_bombplant.h"
#include "main/audio/sfx_trigger_ids.h"
#define BOMBPLANT_OBJFLAG_HITDETECT_DISABLED 0x2000
#define BOMBPLANT_OBJFLAG_RENDERED 0x800

/*
 * State-machine "entered" latch on the per-object flags byte (shared by both
 * BombPlantState and EnemyMushroomState in this DLL). Set alongside every
 * stateIndex assignment; each state handler runs its one-time enter setup on
 * the frame the bit is seen, then clears it.
 */
#define BOMBPLANT_FLAG_MOVE_ACTIVE 0x1
#define BOMBPLANT_FLAG_STATE_ENTERED 0x2
#define BOMBPLANT_GAMEBIT_INTRO_SEEN 0x189 /* one-shot: run intro sequence on first approach */
extern u32 ObjHits_ClearHitVolumes();
extern u32 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern f32 lbl_803E5370;
extern void objRenderFn_8003b8f4(f32);
extern void* getTrickyObject(void);
extern void trickyImpress(u8* obj);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);

extern f32 gBombPlantExplosionScale;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void setMatrixFromObjectPos(void* mtx, void* build);
extern void Matrix_TransformPoint(void* mtx, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern void Obj_SetupObject(int* obj, int a, int b, int c, int d);
extern f32 lbl_803E536C;
extern f32 gBombPlantSporeOffsetScale;
extern f32 gBombPlantGrowRateMin;
extern f32 gBombPlantGrowDuration;
extern int objIsFrozen(u8* obj);
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern u32 ObjHitbox_SetCapsuleBounds();
extern u32 ObjHits_SetHitVolumeSlot();
extern u32 ObjHits_MarkObjectPositionDirty();
extern u32 ObjHits_EnableObject();
extern void* Obj_GetPlayerObject(void);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern void Obj_SetModelColorFadeRecursive(u8* obj, int frames, u8 red, u8 green, u8 blue, u8 startAtHalf);
extern f32 gBombPlantTriggerDistSq;
extern f32 gBombPlantGrowRateDecay;
extern f32 lbl_803E5380;
extern u8 gBombPlantStateTable[];

int bombplant_getExtraSize(void)
{
    return 0x18;
}

int bombplant_getObjectTypeId(void)
{
    return 0;
}

void bombplant_free(void)
{
}

void bombplant_hitDetect(void)
{
}

void bombplant_render(void) { objRenderFn_8003b8f4(lbl_803E5370); }

void fn_801D2B70(int* obj, int unused, int* p3)
{
    BombplantPlacement* p4 = (BombplantPlacement*)((GameObject*)obj)->anim.placementData;
    void* trickyObj = getTrickyObject();
    s16 gbId;
    int i;
    if (trickyObj != NULL)
    {
        trickyImpress(trickyObj);
    }
    Sfx_PlayFromObject(obj, SFXmv_curtainrustle);
    {
        int* p = *(int**)&((GameObject*)obj)->anim.hitReactState;
        ((ObjHitsPriorityState*)p)->flags = (s16)(((ObjHitsPriorityState*)p)->flags | 0x40);
    }
    spawnExplosion((int)obj, gBombPlantExplosionScale, 0, 1, 1, 1, 0, 1, 0);
    ((BombPlantState*)p3)->stateIndex = 1;
    ((BombPlantState*)p3)->flags = (u8)(((BombPlantState*)p3)->flags | BOMBPLANT_FLAG_STATE_ENTERED);
    gbId = p4->gameBit;
    if (gbId != -1)
    {
        GameBit_Set(gbId, 0);
    }
    else
    {
        for (i = 0; i < 3; i++)
        {
            fn_801D29E4(obj, p3);
        }
    }
}

/* EN v1.0 0x801D27B8  size: 172b  Mushroom enemy constructor: seeds the state
 * block, clamps the spin period, offsets the spawn height, flags the model,
 * optionally resets to spawn, and registers in object group 3. */

typedef struct
{
    s16 pos[3];
    f32 w;
    f32 v[3];
} MushSpawnBuild;

/* Spore spawn descriptor (Obj_AllocObjectSetup 0x24): ObjPlacement head
 * extended with the spore's seeded yaw / parent-rotX slots. */
typedef struct
{
    u8 unk00[2];
    s16 unk02;
    u8 color[4];   /* 0x04 */
    f32 posX;      /* 0x08 */
    f32 posY;      /* 0x0c */
    f32 posZ;      /* 0x10 */
    s32 mapId;     /* 0x14 */
    u8 pad18[0x1a - 0x18];
    s16 spawnYaw;  /* 0x1a */
    s16 rotXSeed;  /* 0x1c */
    u8 pad1e[0x24 - 0x1e];
} BombplantSporeSpawn;

/* EN v1.0 0x801D29E4  size: 336b  Spawns a spore object: builds a matrix from
 * the parent's grid pos, transforms a unit offset, and seeds the new object. */
#pragma opt_common_subs off
void fn_801D29E4(int* obj, int* p2)
{
    BombplantSporeSpawn* spore;
    BombplantPlacement* base = (BombplantPlacement*)((GameObject*)obj)->anim.placementData;

    if (Obj_IsLoadingLocked())
    {
        MushSpawnBuild bd;
        f32 mtx[4][4];
        f32 tz, ty, tx;

        spore = Obj_AllocObjectSetup(0x24, 0x198);
        bd.pos[0] = ((GameObject*)obj)->anim.rotX;
        bd.pos[1] = ((GameObject*)obj)->anim.rotY;
        bd.pos[2] = ((GameObject*)obj)->anim.rotZ;
        bd.v[0] = lbl_803E536C;
        bd.v[1] = lbl_803E536C;
        bd.v[2] = lbl_803E536C;
        bd.w = lbl_803E5370;
        setMatrixFromObjectPos(mtx, &bd);
        Matrix_TransformPoint(mtx, lbl_803E536C, lbl_803E5370, lbl_803E536C, &tx, &ty, &tz);
        bd.v[0] = gBombPlantSporeOffsetScale * tx;
        bd.v[1] = gBombPlantSporeOffsetScale * ty;
        bd.v[2] = gBombPlantSporeOffsetScale * tz;
        spore->posX = ((GameObject*)obj)->anim.localPosX + bd.v[0];
        spore->posY = ((GameObject*)obj)->anim.localPosY + bd.v[1];
        spore->posZ = ((GameObject*)obj)->anim.localPosZ + bd.v[2];
        spore->color[1] = 1;
        spore->color[0] = 2;
        spore->spawnYaw = (s16)((s32)base->unk1E << 8);
        spore->rotXSeed = ((GameObject*)obj)->anim.rotX;
        Obj_SetupObject((int*)spore, 5, -1, -1, 0);
    }
}
#pragma opt_common_subs reset

/* EN v1.0 0x801D286C  size: 376b  Bombplant per-tick sequencer: on the armed
 * frame snaps the model to the spawn pose and refreshes hits; otherwise keeps
 * the loop sfx alive, jitters the fuse, and fires the spark particle. */
int bombplant_SeqFn(int* obj)
{
    extern void Sfx_KeepAliveLoopedObjectSound(int* obj, int id); /* #57 */
    extern void ObjHits_RefreshObjectState(int* obj); /* #57 */
    extern int randomGetRange(int lo, int hi); /* #57 */
    float* state = ((GameObject*)obj)->extra;

    if (((EnemyMushroomState*)state)->resetToSpawn != 0)
    {
        int* src;
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        src = *(int**)&((GameObject*)obj)->anim.placementData;
        ((GameObject*)obj)->anim.alpha = 0xff;
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        ((GameObject*)obj)->anim.localPosX = ((BombplantPlacement*)src)->posX;
        ((GameObject*)obj)->anim.localPosY = ((BombplantPlacement*)src)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((BombplantPlacement*)src)->posZ;
        ((GameObject*)obj)->anim.rootMotionScale = gBombPlantGrowRateMin;
        ((EnemyMushroomState*)state)->riseDuration = gBombPlantGrowDuration;
        ((EnemyMushroomState*)state)->heightTarget = ((EnemyMushroomState*)state)->baseScale;
        ((EnemyMushroomState*)state)->riseStep = ((EnemyMushroomState*)state)->heightTarget / ((EnemyMushroomState*)
            state)->riseDuration;
        ((EnemyMushroomState*)state)->timer = ((EnemyMushroomState*)state)->riseDuration;
        ObjHits_RefreshObjectState(obj);
        ((EnemyMushroomState*)state)->resetToSpawn = 0;
        ((EnemyMushroomState*)state)->flags = (u8)(((EnemyMushroomState*)state)->flags | BOMBPLANT_FLAG_STATE_ENTERED);
    }
    else
    {
        int* base;
        u8 flags;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_baddie_eggsnatch_sniff2);
        base = *(int**)&((GameObject*)obj)->anim.placementData;
        flags = ((EnemyMushroomState*)state)->flags;
        if (flags & 0x2)
        {
            int v;
            ((EnemyMushroomState*)state)->flags = (u8)(flags & ~BOMBPLANT_FLAG_STATE_ENTERED);
            v = ((BombplantPlacement*)base)->timerBase + randomGetRange(-0x32, 0x32);
            ((EnemyMushroomState*)state)->timer = v;
        }
        if (((GameObject*)obj)->objectFlags & BOMBPLANT_OBJFLAG_RENDERED)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7f1, NULL, 2, -1, NULL);
        }
    }
    return 0;
}

/* EN v1.0 0x801D1E24  size: 2452b  Mushroom enemy state machine: dormant ->
 * inflate -> chase -> deflate cycle, hit reaction, pop and respawn. */

void bombplant_init(void* obj, void* param, int flag)
{
    extern u32 ObjHits_RefreshObjectState(); /* #57 */
    void* state;
    void* p4c;
    s16 bitId;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)((BombplantPlacement*)param)->objectTypeParam << 8);
    ((GameObject*)obj)->objectFlags |= BOMBPLANT_OBJFLAG_HITDETECT_DISABLED;
    ((GameObject*)obj)->animEventCallback = bombplant_SeqFn;
    ((BombPlantState*)state)->growTargetScale = ((GameObject*)obj)->anim.rootMotionScale;

    if (flag != 0)
    {
        return;
    }

    bitId = ((BombplantPlacement*)param)->gameBit;
    if (bitId != -1 && GameBit_Get(bitId) == 0)
    {
        p4c = ((GameObject*)obj)->anim.placementData;
        ((GameObject*)obj)->anim.alpha = 0xff;
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ((GameObject*)obj)->anim.localPosX = ((BombplantPlacement*)p4c)->posX;
        ((GameObject*)obj)->anim.localPosY = ((BombplantPlacement*)p4c)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((BombplantPlacement*)p4c)->posZ;
        ((GameObject*)obj)->anim.rootMotionScale = gBombPlantGrowRateMin;
        ((BombPlantState*)state)->growDuration = gBombPlantGrowDuration;
        ((BombPlantState*)state)->growStartScale = ((BombPlantState*)state)->growTargetScale;
        ((BombPlantState*)state)->growRate =
            ((BombPlantState*)state)->growStartScale / ((BombPlantState*)state)->growDuration;
        ((BombPlantState*)state)->growTimer = ((BombPlantState*)state)->growDuration;
        ObjHits_RefreshObjectState(obj);
        ((BombPlantState*)state)->stateIndex = 1;
    }
    else
    {
        p4c = ((GameObject*)obj)->anim.placementData;
        ((GameObject*)obj)->anim.alpha = 0xff;
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ((GameObject*)obj)->anim.localPosX = ((BombplantPlacement*)p4c)->posX;
        ((GameObject*)obj)->anim.localPosY = ((BombplantPlacement*)p4c)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((BombplantPlacement*)p4c)->posZ;
        ObjHits_RefreshObjectState(obj);
    }
}

void bombplant_update(void* obj)
{
    extern void Obj_StartModelFadeIn(u8* obj, int frames); /* #57 */
    extern void Sfx_KeepAliveLoopedObjectSound(void* obj, int sndId); /* #57 */
    extern void Sfx_PlayFromObject(void* obj, int sndId); /* #57 */
    extern void fn_801D2B70(void* obj, void* stateEntry, void* state); /* #57 */
    extern u32 ObjHits_RefreshObjectState(); /* #57 */
    extern int randomGetRange(int lo, int hi); /* #57 */
    void* state;
    u8* entry;
    void* param;
    void* p4c;
    void* plr;
    void* p50;
    f32 dist;
    s16 bitId;
    int hitType;
    f32 hit[3];
    f32 lightVec[3];
    int outB;
    int outC;
    int outA;
#define hitX hit[0]
#define hitY hit[1]
#define hitZ hit[2]

    Obj_GetPlayerObject();
    if (objIsFrozen(obj) != 0)
    {
        goto epilogue;
    }

    state = ((GameObject*)obj)->extra;
    entry = &gBombPlantStateTable[((BombPlantState*)state)->stateIndex * 0xc];

    switch (((BombPlantState*)state)->stateIndex)
    {
    case 1:
        param = ((GameObject*)obj)->anim.placementData;
        if ((((BombPlantState*)state)->flags & BOMBPLANT_FLAG_STATE_ENTERED) != 0)
        {
            ((BombPlantState*)state)->flags &= ~BOMBPLANT_FLAG_STATE_ENTERED;
            ((BombPlantState*)state)->growTimer = (f32)(int)((BombplantPlacement*)param)->growTimer;
        }
        bitId = ((BombplantPlacement*)param)->gameBit;
        if (bitId != -1)
        {
            if (GameBit_Get(bitId) != 0)
            {
                plr = Obj_GetPlayerObject();
                dist =
                    vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, (f32*)((u8*)plr + 0x18));
                if (dist > gBombPlantTriggerDistSq)
                {
                    ((BombPlantState*)state)->stateIndex = 2;
                    ((BombPlantState*)state)->flags |= BOMBPLANT_FLAG_STATE_ENTERED;
                }
            }
        }
        else
        {
            f32 t = ((BombPlantState*)state)->growTimer - timeDelta;
            ((BombPlantState*)state)->growTimer = t;
            if (t <= lbl_803E536C)
            {
                plr = Obj_GetPlayerObject();
                dist =
                    vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, (f32*)((u8*)plr + 0x18));
                if (dist > gBombPlantTriggerDistSq)
                {
                    ((BombPlantState*)state)->stateIndex = 2;
                    ((BombPlantState*)state)->flags |= BOMBPLANT_FLAG_STATE_ENTERED;
                }
                ((BombPlantState*)state)->growTimer = lbl_803E536C;
            }
        }
        break;

    case 2:
        if ((((BombPlantState*)state)->flags & BOMBPLANT_FLAG_STATE_ENTERED) != 0)
        {
            Sfx_PlayFromObject(obj, SFXmv_sliftloop11);
            ((BombPlantState*)state)->flags &= ~BOMBPLANT_FLAG_STATE_ENTERED;
            p4c = ((GameObject*)obj)->anim.placementData;
            ((GameObject*)obj)->anim.alpha = 0xff;
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ((GameObject*)obj)->anim.localPosX = ((BombplantPlacement*)p4c)->posX;
            ((GameObject*)obj)->anim.localPosY = ((BombplantPlacement*)p4c)->posY;
            ((GameObject*)obj)->anim.localPosZ = ((BombplantPlacement*)p4c)->posZ;
            ((GameObject*)obj)->anim.rootMotionScale = gBombPlantGrowRateMin;
            ((BombPlantState*)state)->growDuration = gBombPlantGrowDuration;
            ((BombPlantState*)state)->growStartScale = ((BombPlantState*)state)->growTargetScale;
            ((BombPlantState*)state)->growRate =
                ((BombPlantState*)state)->growStartScale / ((BombPlantState*)state)->growDuration;
            ((BombPlantState*)state)->growTimer = ((BombPlantState*)state)->growDuration;
            ObjHits_RefreshObjectState(obj);
        }
        if (((GameObject*)obj)->anim.rootMotionScale > ((BombPlantState*)state)->growStartScale)
        {
            ((BombPlantState*)state)->growRate = ((BombPlantState*)state)->growRate / gBombPlantGrowRateDecay;
        }
        if (((BombPlantState*)state)->growRate < gBombPlantGrowRateMin)
        {
            ((BombPlantState*)state)->growRate = lbl_803E536C;
        }
        ((GameObject*)obj)->anim.rootMotionScale =
            ((BombPlantState*)state)->growRate * timeDelta + ((GameObject*)obj)->anim.rootMotionScale;
        {
            f32 t = ((BombPlantState*)state)->growTimer - timeDelta;
            ((BombPlantState*)state)->growTimer = t;
            if (t < lbl_803E536C)
            {
                ((BombPlantState*)state)->stateIndex = 0;
                ((BombPlantState*)state)->flags |= BOMBPLANT_FLAG_STATE_ENTERED;
            }
        }
        break;

    case 4:
        fn_801D2B70(obj, entry, state);
        break;

    case 0:
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_baddie_eggsnatch_sniff2);
    default:
        param = ((GameObject*)obj)->anim.placementData;
        if ((((BombPlantState*)state)->flags & BOMBPLANT_FLAG_STATE_ENTERED) != 0)
        {
            ((BombPlantState*)state)->flags &= ~BOMBPLANT_FLAG_STATE_ENTERED;
            ((BombPlantState*)state)->growTimer =
                (f32)(int)(((BombplantPlacement*)param)->timerBase + randomGetRange(-0x32, 0x32));
        }
        if ((((GameObject*)obj)->objectFlags & BOMBPLANT_OBJFLAG_RENDERED) != 0)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x7f1, NULL, 2, -1, NULL);
        }
        break;
    }

    if ((entry[8] & 0x1) != 0)
    {
        hitType = ObjHits_GetPriorityHitWithPosition(obj, &outA, &outB, &outC, &hitX,
                                                     &hitY, &hitZ);
        if (hitType != 0 && outC != 0)
        {
            if (hitType == 0x10)
            {
                Obj_StartModelFadeIn(obj, 0x12c);
            }
            else if ((u32)(hitType - 0xe) <= 1 || hitType == 0x11)
            {
                Sfx_PlayFromObject(obj, SFXmv_curtainloop16);
                hitX = hitX + playerMapOffsetX;
                hitZ = hitZ + playerMapOffsetZ;
                objLightFn_8009a1dc(obj, lbl_803E5380, lightVec, 1, 0);
                Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
                ((BombPlantState*)state)->stateIndex = 4;
                ((BombPlantState*)state)->flags |= BOMBPLANT_FLAG_STATE_ENTERED;
                p50 = ((GameObject*)obj)->anim.modelInstance;
                ObjHitbox_SetCapsuleBounds(obj, (s16)(((ObjDef*)p50)->primaryHitboxRadius + 0x50),
                                           (s16)(((ObjDef*)p50)->primaryCapsuleOffsetA - 0x50),
                                           (s16)(((ObjDef*)p50)->primaryCapsuleOffsetB + 0x50));
                ObjHits_MarkObjectPositionDirty(obj);
            }
        }
    }

    if ((entry[8] & 0x8) != 0)
    {
        ObjHits_EnableObject(obj);
    }
    else
    {
        ObjHits_DisableObject(obj);
    }

    if ((entry[8] & 0x10) != 0)
    {
        ObjHits_SetHitVolumeSlot(obj, 5, 1, 0);
    }
    else
    {
        ObjHits_ClearHitVolumes(obj);
    }

    if ((entry[8] & 0x2) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0 && GameBit_Get(BOMBPLANT_GAMEBIT_INTRO_SEEN) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            GameBit_Set(BOMBPLANT_GAMEBIT_INTRO_SEEN, 1);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }

    if ((entry[8] & 0x4) != 0)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }

    if (((GameObject*)obj)->anim.currentMove != *(s16*)entry)
    {
        ObjAnim_SetCurrentMove((int)obj, *(s16*)entry, lbl_803E536C, 0);
    }

    if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
        (int)obj, *(f32*)(entry + 0x4), timeDelta, NULL) != 0)
    {
        ((BombPlantState*)state)->flags |= BOMBPLANT_FLAG_MOVE_ACTIVE;
    }
    else
    {
        ((BombPlantState*)state)->flags &= ~BOMBPLANT_FLAG_MOVE_ACTIVE;
    }

epilogue:
    return;
}
#undef hitX
#undef hitY
#undef hitZ

u8 gBombPlantStateTable[] =
{
    0x00, 0x00, 0x00, 0x00, 0x3B, 0xA3, 0xD7, 0x0A, 0x0B, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x0B, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x3C, 0x03, 0x12, 0x6F, 0x18, 0x00, 0x00, 0x00,
};
