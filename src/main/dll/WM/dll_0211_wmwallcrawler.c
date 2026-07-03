/*
 * wmwallcrawler (DLL 0x211) - the crawling baddies authored for Krazoa
 * Palace (map 'warlock'). UNUSED IN RETAIL: the object def exists
 * (OBJECTS.bin 913 'WM_WallCraw', type 0x275) but no romlist on any of
 * the 124 maps places one - the palace's shipped enemies are HagabonMK2
 * and sharpclaw groups. Likely a Dinosaur Planet-era Warlock Mountain
 * enemy (the Tricky-flee variant flag predates the retail rule that the
 * sidekick never enters the palace).
 * Each crawler perches at its spawn point until the player (or, for the
 * WMWALLCRAWLER_FLAG_TARGET_NEAREST variant, the nearest group-10
 * object) comes within triggerRadius, then dives to its home height and
 * chases along the surface, lunging (anim move 2) and striking on
 * contact. When its life timer expires it flees and either re-perches,
 * despawns, or plays its death anim (WMWALLCRAWLER_FLAG_DEATH_ANIM).
 * Per-placement behaviour comes from the variant flag table
 * gWallCrawlerVariantFlags. All crawlers despawn for good once the six progress
 * game bits 0x2AA-0x2AF are set.
 */
#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"
#include "main/dll/path_control_interface.h"
#include "main/obj_placement.h"
#include "main/vecmath.h"
#include "main/dll/WM/dll_0211_wmwallcrawler.h"

typedef struct WmwallcrawlerState
{
    u8 pathState[0x268]; /* 0x000: PathControlInterface state block */
    f32 triggerRadius;   /* 0x268: aggro radius, from placement; rescaled after each dive */
    f32 unk26C;          /* 0x26C: threshold vs lbl_803E5FD0, set once at init */
    f32 homeX;           /* 0x270: home position, from placement */
    f32 homeY;           /* 0x274 */
    f32 homeZ;           /* 0x278 */
    u8 pad27C[0x284 - 0x27C];
    f32 animSpeed;       /* 0x284: ObjAnim_AdvanceCurrentMove rate */
    s16 attackTimer;     /* 0x288: strike cooldown (float-param, timerCountDown) */
    s16 explodeTimer;    /* 0x28A: TIMED_EXPLODE countdown to the particle burst */
    s16 despawnTimer;    /* 0x28C: post-burst countdown; render gates on 0 */
    s16 heightOffset;    /* 0x28E: from placement, added to homeY for the perch */
    s16 lifeTimer;       /* 0x290: frames until the crawler retreats/expires */
    s16 counterGameBit;  /* 0x292: incremented when the death anim completes (0/-1 = none) */
    u16 flags;           /* 0x294: WMWALLCRAWLER_FLAG_*, from gWallCrawlerVariantFlags[variant] */
    s8 mode;             /* 0x296: WMWALLCRAWLER_MODE_* */
    u8 pad297;
    u8 variant;          /* 0x298: placement byte indexing the flag table */
    u8 hitBits;          /* 0x299: bit 0 = hit recorded, consumed by hitDetect (WcHitBits) */
    u8 pad29A[0x29C - 0x29A];
} WmwallcrawlerState;

STATIC_ASSERT(offsetof(WmwallcrawlerState, triggerRadius) == 0x268);
STATIC_ASSERT(offsetof(WmwallcrawlerState, homeX) == 0x270);
STATIC_ASSERT(offsetof(WmwallcrawlerState, animSpeed) == 0x284);
STATIC_ASSERT(offsetof(WmwallcrawlerState, attackTimer) == 0x288);
STATIC_ASSERT(offsetof(WmwallcrawlerState, despawnTimer) == 0x28C);
STATIC_ASSERT(offsetof(WmwallcrawlerState, lifeTimer) == 0x290);
STATIC_ASSERT(offsetof(WmwallcrawlerState, counterGameBit) == 0x292);
STATIC_ASSERT(offsetof(WmwallcrawlerState, flags) == 0x294);
STATIC_ASSERT(offsetof(WmwallcrawlerState, mode) == 0x296);
STATIC_ASSERT(offsetof(WmwallcrawlerState, variant) == 0x298);
STATIC_ASSERT(offsetof(WmwallcrawlerState, hitBits) == 0x299);
STATIC_ASSERT(sizeof(WmwallcrawlerState) == 0x29C);

typedef struct WmwallcrawlerMapData
{
    ObjPlacement base;
    s8 rotXByte;        /* 0x18: rotX in 1/256 turns */
    u8 variant;         /* 0x19: index into the flag table gWallCrawlerVariantFlags */
    s16 triggerRadius;  /* 0x1A */
    s16 heightOffset;   /* 0x1C */
    s16 counterGameBit; /* 0x1E */
} WmwallcrawlerMapData;

STATIC_ASSERT(offsetof(WmwallcrawlerMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WmwallcrawlerMapData, variant) == 0x19);
STATIC_ASSERT(offsetof(WmwallcrawlerMapData, triggerRadius) == 0x1A);
STATIC_ASSERT(offsetof(WmwallcrawlerMapData, heightOffset) == 0x1C);
STATIC_ASSERT(offsetof(WmwallcrawlerMapData, counterGameBit) == 0x1E);
STATIC_ASSERT(sizeof(WmwallcrawlerMapData) == 0x20);

/* state->flags, from the per-variant table gWallCrawlerVariantFlags */
#define WMWALLCRAWLER_FLAG_START_ACTIVE 0x1    /* spawn already diving (rotZ 0) */
#define WMWALLCRAWLER_FLAG_PATH_CONTROL 0x2    /* drive movement through gPathControlInterface */
#define WMWALLCRAWLER_FLAG_FLOOR_SNAP 0x4      /* snap Y to the nearest floor (hitDetectFn_80065e50) */
#define WMWALLCRAWLER_FLAG_TIMED_EXPLODE 0x8   /* burst into particles when explodeTimer expires */
#define WMWALLCRAWLER_FLAG_TARGET_NEAREST 0x10 /* chase the nearest group-10 object, not the player */
#define WMWALLCRAWLER_FLAG_CLAMP_SPEED 0x20    /* cap velocity at gWallCrawlerSpeedCap */
#define WMWALLCRAWLER_FLAG_FADE_IN 0x40        /* spawn at alpha 0, fade in during render */
#define WMWALLCRAWLER_FLAG_NO_RETREAT 0x80     /* ignore lifeTimer (never re-perch/expire) */
#define WMWALLCRAWLER_FLAG_DEATH_ANIM 0x100    /* play the death anim instead of despawning */
#define WMWALLCRAWLER_FLAG_TRICKY_FLEE 0x200   /* flee when Tricky closes in; random re-dive */
#define WMWALLCRAWLER_FLAG_ATTACK_MOVE 0x400   /* lunge (anim move 2) when close */

/* state->mode */
enum
{
    WMWALLCRAWLER_MODE_IDLE = 0,    /* perched at spawn height */
    WMWALLCRAWLER_MODE_DESCEND = 1, /* dropping to home height */
    WMWALLCRAWLER_MODE_CHASE = 3,   /* tracking the target along the surface */
    WMWALLCRAWLER_MODE_FLEE = 5,    /* reversed away from the target, life timer running */
    WMWALLCRAWLER_MODE_DIE = 6      /* death anim, then free/hide */
};

extern int getTrickyObject(void);
extern void Obj_RemoveFromUpdateList(int obj);
extern int fn_80080150(void* timer);
extern int randFn_80080100(int n);
extern f32 sqrtf(f32 x);
extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern f32 gWallCrawlerSpeedCap;
extern u8 gWallCrawlerHitCount;
extern f32 lbl_803E5FB0;
extern f32 lbl_803E5FBC;
extern f32 lbl_803E5FC0;
extern f32 lbl_803E5FC4;
extern f32 lbl_803E5FC8;
extern f32 lbl_803E5FCC;
extern f32 lbl_803E5FD0;
extern f32 lbl_803E5FD4;
extern f32 lbl_803E5FD8;
extern f32 lbl_803E5FDC;
extern f32 lbl_803E5FE0;
extern f32 lbl_803E5FE4;
extern f32 lbl_803E5FE8;
extern f32 lbl_803E5FEC;
extern f32 lbl_803E5FF0;
extern f32 lbl_803E5FF4;
extern f32 lbl_803E5FF8;
extern f32 lbl_803E5FFC;
extern f32 lbl_803E6000;
extern f32 lbl_803E6004;
extern f32 lbl_803E6008;
extern f32 lbl_803E600C;
extern f32 lbl_803E6010;
extern f32 lbl_803E6014;
extern f32 lbl_803E6018;

extern void vecRotateZXY(void* mtx, f32* vec);
extern f32 lbl_803E5FB8;
extern u16 gWallCrawlerVariantFlags[];
extern u8 gWallCrawlerPointCollision[];
extern u8 sWallCrawlerCollisionBone;
extern f32 lbl_803E6030;
extern f32 lbl_803E6034;

/* overlay of state->hitBits */
typedef struct
{
    u8 hit : 1;
    u8 _r299 : 7;
} WcHitBits;

typedef struct
{
    s16 r0, r1, r2;
    f32 m8, mc, m10, m14;
} WcXf;

int wmwallcrawler_animEventCallback(int obj)
{
    ((WmwallcrawlerState*)((GameObject*)obj)->extra)->mode = WMWALLCRAWLER_MODE_DESCEND;
    return 0;
}

/* dont_inline: defined before its update call sites (address order),
   but the retail unit keeps both bls. No same-TU callees, so the wrap
   is safe (see the dont_inline CAUTION in the playbook). */
#pragma dont_inline on
void wmwallcrawler_alignToFloorNormal(int obj, f32* floorData)
{
    WcXf mtx;
    f32 in[3];
    u16 ang, ang2;
    in[0] = floorData[1];
    in[1] = floorData[2];
    in[2] = floorData[3];
    mtx.mc = lbl_803E5FB0;
    mtx.m10 = lbl_803E5FB0;
    mtx.m14 = lbl_803E5FB0;
    mtx.m8 = lbl_803E5FB4;
    mtx.r2 = 0;
    mtx.r1 = 0;
    mtx.r0 = ((GameObject*)obj)->anim.rotX;
    vecRotateZXY(&mtx, in);
    ang = getAngle(in[0], in[1]);
    ang2 = getAngle(in[2], in[1]);
    ((GameObject*)obj)->anim.rotY = ang2;
    ((GameObject*)obj)->anim.rotZ = ang;
}
#pragma dont_inline reset

int wmwallcrawler_getExtraSize(void) { return sizeof(WmwallcrawlerState); }

int wmwallcrawler_getObjectTypeId(void) { return 0x0; }

void wmwallcrawler_free(int obj)
{
    ObjGroup_RemoveObject(obj, 3);
}

void wmwallcrawler_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    ObjAnimComponent* objAnim = &((GameObject*)p1)->anim;
    int* inner = ((GameObject*)p1)->extra;
    if ((((WmwallcrawlerState*)inner)->flags & WMWALLCRAWLER_FLAG_FADE_IN) != 0 && objAnim->alpha < 0xff)
    {
        if (objAnim->alpha > 0xff - framesThisStep)
        {
            objAnim->alpha = 0xff;
            ((WmwallcrawlerState*)inner)->flags &= ~WMWALLCRAWLER_FLAG_FADE_IN;
        }
        else
        {
            objAnim->alpha += framesThisStep;
        }
    }
    if (vis != 0 && ((WmwallcrawlerState*)inner)->despawnTimer == 0)
    {
        objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E5FB4); /* 1.0f */
    }
}

void wmwallcrawler_hitDetect(int obj)
{
    WmwallcrawlerState* state = ((GameObject*)obj)->extra;
    f32 stk = lbl_803E5FB8;
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
    {
        if ((state->flags & WMWALLCRAWLER_FLAG_DEATH_ANIM) != 0)
        {
            state->mode = WMWALLCRAWLER_MODE_DIE;
        }
        else if (*(void**)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) == NULL)
        {
            ObjHits_DisableObject(obj);
            Obj_FreeObject(obj);
        }
        else
        {
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
            ObjGroup_RemoveObject(obj, 3);
            ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
        }
    }
    else if (((WcHitBits*)&state->hitBits)->hit != 0)
    {
        int target;
        if ((state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0)
        {
            target = (int)Obj_GetPlayerObject();
        }
        else
        {
            target = ObjGroup_FindNearestObject(0xa, obj, &stk);
        }
        ObjHits_RecordObjectHit(target, obj, 0xb, 1, 0);
        state->mode = WMWALLCRAWLER_MODE_DIE;
        ((WcHitBits*)&state->hitBits)->hit = 0;
    }
}

void wmwallcrawler_update(int obj)
{
    int bestIdx;
    u32 player;
    u8* st;
    f32 speed;
    int k;
    int n;
    int idx;
    u32 tricky;
    u8 sum;
    int ang;
    f32 dist;
    f32 sq;
    f32** walk;
    s8 mode;
    f32** list;
    f32** list2;
    ObjHitsPriorityState* hitState;
    f32 best;
    f32 d;
    f32 dy;
    f32 dz;

    st = ((GameObject*)obj)->extra;
    bestIdx = 0;
    speed = lbl_803E5FB4;
    sum = 0;
    list = 0;
    best = lbl_803E5FBC;
    player = (((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0
        ? (u32)Obj_GetPlayerObject()
        : ObjGroup_FindNearestObject(10, obj, &best);
    if (player != 0)
    {
        sq = GameBit_Get(0x789);
        gWallCrawlerSpeedCap = lbl_803E5FC0 * sq + lbl_803E5FC0;
        if (((WmwallcrawlerState*)st)->mode == WMWALLCRAWLER_MODE_DIE)
        {
            ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            if (((GameObject*)obj)->anim.currentMove != 1)
            {
                ObjAnim_SetCurrentMove(obj, 1, lbl_803E5FB0, 0);
                Sfx_PlayFromObject(obj, 0x73);
            }
            if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E5FC4)
            {
                ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5FC8;
            }
            if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
                obj, lbl_803E5FCC, framesThisStep, NULL) != 0)
            {
                if (((WmwallcrawlerState*)st)->counterGameBit != 0 && ((WmwallcrawlerState*)st)->counterGameBit != -1)
                {
                    GameBit_Set(((WmwallcrawlerState*)st)->counterGameBit, GameBit_Get(((WmwallcrawlerState*)st)->counterGameBit) + 1);
                }
                if (*(void**)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) == 0)
                {
                    ObjHits_DisableObject(obj);
                    Obj_FreeObject(obj);
                }
                else
                {
                    Obj_RemoveFromUpdateList(obj);
                    ObjHits_DisableObject(obj);
                    ObjGroup_RemoveObject(obj, 3);
                    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
            }
        }
        else
        {
            if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_TIMED_EXPLODE) != 0)
            {
                if (timerCountDown(st + 0x28a) != 0)
                {
                    for (k = 0; k < 0x1e; k++)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x1a3, NULL, 0, -1, NULL);
                    }
                    s16toFloat(st + 0x28c, 100);
                    return;
                }
                if (timerCountDown(st + 0x28c) != 0)
                {
                    ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                    if (*(void**)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) == 0)
                    {
                        ObjHits_DisableObject(obj);
                        Obj_FreeObject(obj);
                    }
                    else
                    {
                        Obj_RemoveFromUpdateList(obj);
                        ObjHits_DisableObject(obj);
                        ObjGroup_RemoveObject(obj, 3);
                        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    }
                    return;
                }
            }
            for (k = 0; k < 6; k++)
            {
                sum += GameBit_Get(k + 0x2aa);
            }
            if (sum >= 6)
            {
                if (*(void**)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) == 0)
                {
                    ObjHits_DisableObject(obj);
                    Obj_FreeObject(obj);
                }
                else
                {
                    Obj_RemoveFromUpdateList(obj);
                    ObjHits_DisableObject(obj);
                    ObjGroup_RemoveObject(obj, 3);
                    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
            }
            else
            {
                if (fn_80080150(st + 0x288) != 0)
                {
                    timerCountDown(st + 0x288);
                }
                else
                {
                    mode = ((WmwallcrawlerState*)st)->mode;
                    if ((mode == WMWALLCRAWLER_MODE_CHASE || mode == WMWALLCRAWLER_MODE_DESCEND || mode == WMWALLCRAWLER_MODE_FLEE) && (((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_NO_RETREAT) == 0)
                    {
                        if (mode == WMWALLCRAWLER_MODE_FLEE)
                        {
                            if (lbl_803E5FD0 > lbl_803E5FD4 + ((WmwallcrawlerState*)st)->unk26C)
                            {
                                ((WmwallcrawlerState*)st)->mode = WMWALLCRAWLER_MODE_CHASE;
                                ((WmwallcrawlerState*)st)->attackTimer = 0x14;
                            }
                        }
                        else if (lbl_803E5FD0 < ((WmwallcrawlerState*)st)->unk26C)
                        {
                            ((WmwallcrawlerState*)st)->lifeTimer -= framesThisStep;
                            if (randFn_80080100(0x32) != 0)
                            {
                                Sfx_PlayFromObject(obj, 0x74);
                            }
                            if (((WmwallcrawlerState*)st)->lifeTimer <= 0)
                            {
                                if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_DEATH_ANIM) != 0)
                                {
                                    ((WmwallcrawlerState*)st)->mode = WMWALLCRAWLER_MODE_DIE;
                                }
                                else if (*(void**)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) == 0)
                                {
                                    ObjHits_DisableObject(obj);
                                    Obj_FreeObject(obj);
                                }
                                else
                                {
                                    Obj_RemoveFromUpdateList(obj);
                                    ObjHits_DisableObject(obj);
                                    ObjGroup_RemoveObject(obj, 3);
                                    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                                }
                                return;
                            }
                            if (((WmwallcrawlerState*)st)->mode != WMWALLCRAWLER_MODE_FLEE)
                            {
                                Sfx_StopObjectChannel(obj, 0x10);
                                ((WmwallcrawlerState*)st)->mode = WMWALLCRAWLER_MODE_FLEE;
                                ((GameObject*)obj)->anim.velocityX = -((GameObject*)obj)->anim.velocityX * (d = lbl_803E5FD8);
                                ((GameObject*)obj)->anim.velocityZ = -((GameObject*)obj)->anim.velocityZ * d;
                            }
                        }
                    }
                    if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_TRICKY_FLEE) != 0 && ((WmwallcrawlerState*)st)->mode != WMWALLCRAWLER_MODE_FLEE &&
                        (tricky = getTrickyObject()) != 0 &&
                        Vec_distance((void*)(obj + 0x18), (void*)(tricky + 0x18)) < lbl_803E5FD4 &&
                        (**(u8 (**)(int))(*(int*)(*(int*)(tricky + 0x68)) + 0x44))(tricky) != 0)
                    {
                        ((WmwallcrawlerState*)st)->mode = WMWALLCRAWLER_MODE_FLEE;
                        Sfx_PlayFromObject(obj, 0x74);
                    }
                    if (((WmwallcrawlerState*)st)->mode == WMWALLCRAWLER_MODE_FLEE)
                    {
                        if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_PATH_CONTROL) != 0)
                        {
                            (*gPathControlInterface)->update((void*)obj, st, timeDelta);
                            (*gPathControlInterface)->apply((void*)obj, st);
                            (*gPathControlInterface)->advance((void*)obj, st, timeDelta);
                        }
                        sq = ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ;
                        if (lbl_803E5FB0 != sq)
                        {
                            speed = sqrtf(sq);
                        }
                        ((WmwallcrawlerState*)st)->animSpeed = lbl_803E5FDC * speed;
                        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(
                            obj, ((WmwallcrawlerState*)st)->animSpeed, framesThisStep,
                            NULL);
                        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.localPosX;
                        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.localPosZ;
                        ((WmwallcrawlerState*)st)->lifeTimer -= framesThisStep;
                        if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_FLOOR_SNAP) != 0)
                        {
                            best = lbl_803E5FBC;
                            n = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                                     &list, 0, 0);
                            idx = 0;
                            for (k = 0; k < n; k++)
                            {
                                d = *list[idx] - ((GameObject*)obj)->anim.localPosY;
                                if (d < *(f32*)&lbl_803E5FB0)
                                {
                                    d = d * *(f32*)&lbl_803E5FE0;
                                }
                                if (d < best)
                                {
                                    bestIdx = idx;
                                    best = d;
                                }
                                idx++;
                            }
                            if (list != 0)
                            {
                                ((GameObject*)obj)->anim.localPosY = *list[bestIdx];
                                wmwallcrawler_alignToFloorNormal(obj, list[bestIdx]);
                            }
                            else
                            {
                                ((GameObject*)obj)->anim.localPosY = ((WmwallcrawlerState*)st)->homeY;
                            }
                        }
                        else
                        {
                            ((GameObject*)obj)->anim.localPosY = ((WmwallcrawlerState*)st)->homeY;
                        }
                        if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_NO_RETREAT) == 0 && ((WmwallcrawlerState*)st)->lifeTimer <= 0)
                        {
                            if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_DEATH_ANIM) != 0)
                            {
                                ((WmwallcrawlerState*)st)->mode = WMWALLCRAWLER_MODE_DIE;
                            }
                            else
                            {
                                ((WmwallcrawlerState*)st)->mode = WMWALLCRAWLER_MODE_IDLE;
                                Sfx_StopObjectChannel(obj, 0x18);
                                ((GameObject*)obj)->anim.localPosX = ((WmwallcrawlerState*)st)->homeX;
                                ((GameObject*)obj)->anim.localPosY = ((WmwallcrawlerState*)st)->homeY + (f32)((WmwallcrawlerState*)st)->heightOffset;
                                ((GameObject*)obj)->anim.localPosZ = ((WmwallcrawlerState*)st)->homeZ;
                            }
                        }
                        else if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_TRICKY_FLEE) != 0 && (int)randomGetRange(0, 0x14) == 0)
                        {
                            ((WmwallcrawlerState*)st)->mode = WMWALLCRAWLER_MODE_CHASE;
                            s16toFloat(st + 0x288, (s16)(randomGetRange(0, 0x14) + 0x32));
                        }
                    }
                    else
                    {
                        dist = Vec_xzDistance((f32*)(player + 0x18), (f32*)(obj + 0x18));
                        if (dist < ((WmwallcrawlerState*)st)->triggerRadius || GameBit_Get(0x1d9) != 0)
                        {
                            mode = ((WmwallcrawlerState*)st)->mode;
                            if (mode == WMWALLCRAWLER_MODE_IDLE)
                            {
                                ((WmwallcrawlerState*)st)->mode = WMWALLCRAWLER_MODE_DESCEND;
                                s16toFloat(st + 0x288, 2);
                                ((GameObject*)obj)->anim.rotZ = 0;
                            }
                            else if (mode == WMWALLCRAWLER_MODE_DESCEND)
                            {
                                if (((GameObject*)obj)->anim.velocityY > lbl_803E5FE4)
                                {
                                    ((GameObject*)obj)->anim.velocityY = lbl_803E5FE8 * timeDelta + ((GameObject*)obj)->anim.velocityY;
                                }
                                if (((GameObject*)obj)->anim.localPosY < ((WmwallcrawlerState*)st)->homeY)
                                {
                                    ((GameObject*)obj)->anim.localPosY = ((WmwallcrawlerState*)st)->homeY;
                                    ((GameObject*)obj)->anim.velocityY = lbl_803E5FB0;
                                    ((WmwallcrawlerState*)st)->mode = WMWALLCRAWLER_MODE_CHASE;
                                    s16toFloat(st + 0x288, (s16)(randomGetRange(0, 0x14) + 0x32));
                                    ((WmwallcrawlerState*)st)->triggerRadius = ((WmwallcrawlerState*)st)->triggerRadius * lbl_803E5FEC;
                                    ObjAnim_SetCurrentMove(obj, 0, lbl_803E5FB0, 0);
                                }
                            }
                            else if (mode == WMWALLCRAWLER_MODE_CHASE)
                            {
                                Sfx_PlayFromObject(obj, 0x47);
                                if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_PATH_CONTROL) != 0)
                                {
                                    (*gPathControlInterface)->update((void*)obj, st, timeDelta);
                                    (*gPathControlInterface)->apply((void*)obj, st);
                                    (*gPathControlInterface)->advance((void*)obj, st, timeDelta);
                                }
                                if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_FLOOR_SNAP) != 0)
                                {
                                    best = lbl_803E5FBC;
                                    n = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                                             ((GameObject*)obj)->anim.localPosZ, &list, 0, 0);
                                    idx = 0;
                                    for (k = 0; k < n; k++)
                                    {
                                        d = *list[idx] - ((GameObject*)obj)->anim.localPosY;
                                        if (d < *(f32*)&lbl_803E5FB0)
                                        {
                                            d = d * *(f32*)&lbl_803E5FE0;
                                        }
                                        if (d < best)
                                        {
                                            bestIdx = idx;
                                            best = d;
                                        }
                                        idx++;
                                    }
                                    if (list != 0)
                                    {
                                        ((GameObject*)obj)->anim.localPosY = *list[bestIdx];
                                        wmwallcrawler_alignToFloorNormal(obj, list[bestIdx]);
                                    }
                                    else
                                    {
                                        ((GameObject*)obj)->anim.localPosY = ((WmwallcrawlerState*)st)->homeY;
                                    }
                                }
                                else
                                {
                                    ((GameObject*)obj)->anim.localPosY = ((WmwallcrawlerState*)st)->homeY;
                                }
                                dy = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
                                dz = ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
                                sq = (((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX) / (d = lbl_803E5FF0);
                                ((GameObject*)obj)->anim.velocityX = sq * timeDelta;
                                sq = dy / d;
                                ((GameObject*)obj)->anim.velocityY = sq * timeDelta;
                                sq = dz / d;
                                ((GameObject*)obj)->anim.velocityZ = sq * timeDelta;
                                if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_CLAMP_SPEED) != 0 &&
                                    sqrtf(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
                                        (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                                        ((GameObject*)obj)->anim.velocityY * ((GameObject*)obj)->anim.velocityY)) > gWallCrawlerSpeedCap)
                                {
                                    Vec3_Normalize((f32*)(obj + 0x24));
                                    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (timeDelta * gWallCrawlerSpeedCap);
                                    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * (timeDelta * gWallCrawlerSpeedCap);
                                    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * (timeDelta * gWallCrawlerSpeedCap);
                                }
                                if (((GameObject*)obj)->anim.currentMove == 0 && (((WmwallcrawlerState*)st)->flags &
                                    WMWALLCRAWLER_FLAG_ATTACK_MOVE) != 0 && dist < lbl_803E5FF4)
                                {
                                    ObjAnim_SetCurrentMove(obj, 2, lbl_803E5FB0, 0);
                                }
                                hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
                                if (dist < lbl_803E5FF8 ||
                                    ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) != 0 &&
                                        (hitState->flags & 8) != 0 &&
                                        dist < lbl_803E5FFC))
                                {
                                    gWallCrawlerHitCount += 1;
                                    if (((GameObject*)obj)->anim.currentMove == 2 && ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E6000
                                        && ((GameObject*)obj)->anim.currentMoveProgress < lbl_803E6004)
                                    {
                                        ObjMsg_SendToObject(player, 0x60004, obj, 1);
                                        gWallCrawlerHitCount = 0;
                                    }
                                    if (GameBit_Get(0x1d9) != 0)
                                    {
                                        gWallCrawlerHitCount = 0;
                                    }
                                    else if (gWallCrawlerHitCount >= 3 || ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) != 0 &&
                                        gWallCrawlerHitCount >= 3))
                                    {
                                        Sfx_PlayFromObject(obj, 0x75);
                                        if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0)
                                        {
                                            ObjMsg_SendToObject(player, 0x60004, obj, 1);
                                        }
                                        else
                                        {
                                            ((WcHitBits*)(st + 0x299))->hit = 1;
                                        }
                                        gWallCrawlerHitCount = 0;
                                    }
                                    if ((((WmwallcrawlerState*)st)->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0)
                                    {
                                        d = lbl_803E6008;
                                        ((GameObject*)obj)->anim.localPosX = d * -((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->anim.localPosX;
                                        ((GameObject*)obj)->anim.localPosZ = d * -((GameObject*)obj)->anim.velocityZ + ((GameObject*)obj)->anim.localPosZ;
                                    }
                                    else
                                    {
                                        d = lbl_803E600C;
                                        ((GameObject*)obj)->anim.localPosX = d * -((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->anim.localPosX;
                                        ((GameObject*)obj)->anim.localPosZ = d * -((GameObject*)obj)->anim.velocityZ + ((GameObject*)obj)->anim.localPosZ;
                                    }
                                    s16toFloat(st + 0x288, (s16)(randomGetRange(0, 0x14) + 100));
                                }
                                ang = getAngle(((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX,
                                               ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ);
                                ((GameObject*)obj)->anim.rotX = ang + 0x7fff;
                                sq = ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ;
                                if (lbl_803E5FB0 != sq)
                                {
                                    speed = sqrtf(sq);
                                }
                                switch (((GameObject*)obj)->anim.currentMove)
                                {
                                case 0:
                                    ((WmwallcrawlerState*)st)->animSpeed = lbl_803E6010 * speed;
                                    break;
                                case 2:
                                    ((WmwallcrawlerState*)st)->animSpeed = lbl_803E6014;
                                    break;
                                case 1:
                                    ((WmwallcrawlerState*)st)->animSpeed = lbl_803E5FCC;
                                    break;
                                }
                                if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(
                                    obj, ((WmwallcrawlerState*)st)->animSpeed, framesThisStep,
                                    NULL) != 0 && ((GameObject*)obj)->anim.currentMove != 0)
                                {
                                    ObjAnim_SetCurrentMove(obj, 0, lbl_803E5FB0, 0);
                                }
                                ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.localPosX;
                                ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.localPosZ;
                            }
                        }
                        else if (((WmwallcrawlerState*)st)->mode == WMWALLCRAWLER_MODE_DESCEND)
                        {
                            if (((GameObject*)obj)->anim.velocityY > lbl_803E5FE0)
                            {
                                ((GameObject*)obj)->anim.velocityY = lbl_803E6018 * timeDelta + ((GameObject*)obj)->anim.velocityY;
                            }
                            if (((GameObject*)obj)->anim.localPosY < ((WmwallcrawlerState*)st)->homeY)
                            {
                                ((GameObject*)obj)->anim.localPosY = ((WmwallcrawlerState*)st)->homeY;
                                ((GameObject*)obj)->anim.velocityY = lbl_803E5FB0;
                                ((WmwallcrawlerState*)st)->mode = WMWALLCRAWLER_MODE_CHASE;
                                s16toFloat(st + 0x288, (s16)(randomGetRange(0, 0x14) + 0x32));
                                ((WmwallcrawlerState*)st)->triggerRadius = ((WmwallcrawlerState*)st)->triggerRadius * lbl_803E5FEC;
                                ObjAnim_SetCurrentMove(obj, 0, lbl_803E5FB0, 0);
                            }
                            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY;
                        }
                        if (((WmwallcrawlerState*)st)->mode == WMWALLCRAWLER_MODE_IDLE)
                        {
                            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY;
                        }
                        if (randFn_80080100(0x32) != 0)
                        {
                            Sfx_PlayFromObject(obj, 0x76);
                        }
                    }
                }
            }
        }
    }
}

void wmwallcrawler_init(int obj, int spawn)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    WmwallcrawlerState* state = ((GameObject*)obj)->extra;
    u16 flags;
    WmwallcrawlerMapData* mapData = (WmwallcrawlerMapData*)spawn;
    ObjGroup_AddObject(obj, 3);
    ((GameObject*)obj)->anim.rotX = (s16)(mapData->rotXByte << 8);
    ObjMsg_AllocQueue(obj, 2);
    state->homeX = mapData->base.posX;
    state->homeY = mapData->base.posY;
    state->homeZ = mapData->base.posZ;
    state->triggerRadius = (f32)(int)mapData->triggerRadius;
    state->variant = mapData->variant;
    state->flags = gWallCrawlerVariantFlags[state->variant];
    storeZeroToFloatParam(&state->explodeTimer);
    storeZeroToFloatParam(&state->despawnTimer);
    storeZeroToFloatParam(&state->attackTimer);
    flags = state->flags;
    if ((flags & WMWALLCRAWLER_FLAG_START_ACTIVE) != 0)
    {
        ((GameObject*)obj)->anim.rotZ = 0;
        state->mode = WMWALLCRAWLER_MODE_DESCEND;
    }
    else if ((flags & WMWALLCRAWLER_FLAG_TIMED_EXPLODE) != 0)
    {
        s16toFloat(&state->explodeTimer, 0x4b0);
        state->triggerRadius = lbl_803E6030;
        ((GameObject*)obj)->anim.rotZ = 0;
        state->mode = WMWALLCRAWLER_MODE_DESCEND;
    }
    else
    {
        s16toFloat(&state->attackTimer, 0x190);
        ((GameObject*)obj)->anim.rotZ = -0x7fff;
        state->mode = WMWALLCRAWLER_MODE_IDLE;
    }
    if ((state->flags & WMWALLCRAWLER_FLAG_FADE_IN) != 0)
    {
        objAnim->alpha = 0;
    }
    state->animSpeed = lbl_803E5FB0;
    state->heightOffset = mapData->heightOffset;
    ((GameObject*)obj)->anim.localPosY = mapData->base.posY + (f32)(int)state->heightOffset;
    state->lifeTimer = (s16)(randomGetRange(0, 0x50) + 0x190);
    state->unk26C = lbl_803E6034;
    state->counterGameBit = mapData->counterGameBit;
    if ((state->flags & WMWALLCRAWLER_FLAG_PATH_CONTROL) != 0)
    {
        state->pathState[0x25b] = 1;
        (*gPathControlInterface)->init((void*)state, 0, 0, 1);
        (*gPathControlInterface)->setLocalPointCollision((void*)state, 1, gWallCrawlerPointCollision,
                                                         &sWallCrawlerCollisionBone, 4);
        (*gPathControlInterface)->attachObject((void*)obj, state);
        *(u32*)state |= 0x40008;
    }
    ((GameObject*)obj)->animEventCallback = wmwallcrawler_animEventCallback;
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
}

void wmwallcrawler_release(void)
{
}

void wmwallcrawler_initialise(void)
{
}

u16 gWallCrawlerVariantFlags[8] = { 0x0000, 0x0002, 0x0004, 0x0001, 0x000C, 0x03F7, 0x0167, 0x050C };
u8 gWallCrawlerPointCollision[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
