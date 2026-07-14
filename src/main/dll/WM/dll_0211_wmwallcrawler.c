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
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/object.h"
#include "main/track_dolphin_api.h"
#include "main/maketex_random_api.h"
#include "main/maketex_timer_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/obj_message.h"
#include "main/objhits.h"
#include "main/object_api.h"
#include "main/object_update_list.h"
#include "main/dll/path_control_interface.h"
#include "main/obj_placement.h"
#include "main/vecmath.h"
#include "main/dll/WM/dll_0211_wmwallcrawler.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

f32 gWallCrawlerSpeedCap = 0.1f;
u8 sWallCrawlerCollisionBone[3] = {0x41, 0x20, 0};

#define WMWALLCRAWLER_OBJGROUP        3
#define WMWALLCRAWLER_PARTFX          0x1a3
#define WMWALLCRAWLER_TARGET_OBJGROUP 0xa /* nearest group-10 object targeted by the TARGET_NEAREST variant */

/* state->flags, from the per-variant table gWallCrawlerVariantFlags */
#define WMWALLCRAWLER_FLAG_START_ACTIVE   0x1   /* spawn already diving (rotZ 0) */
#define WMWALLCRAWLER_FLAG_PATH_CONTROL   0x2   /* drive movement through gPathControlInterface */
#define WMWALLCRAWLER_FLAG_FLOOR_SNAP     0x4   /* snap Y to the nearest floor (hitDetectFn_80065e50) */
#define WMWALLCRAWLER_FLAG_TIMED_EXPLODE  0x8   /* burst into particles when explodeTimer expires */
#define WMWALLCRAWLER_FLAG_TARGET_NEAREST 0x10  /* chase the nearest group-10 object, not the player */
#define WMWALLCRAWLER_FLAG_CLAMP_SPEED    0x20  /* cap velocity at gWallCrawlerSpeedCap */
#define WMWALLCRAWLER_FLAG_FADE_IN        0x40  /* spawn at alpha 0, fade in during render */
#define WMWALLCRAWLER_FLAG_NO_RETREAT     0x80  /* ignore lifeTimer (never re-perch/expire) */
#define WMWALLCRAWLER_FLAG_DEATH_ANIM     0x100 /* play the death anim instead of despawning */
#define WMWALLCRAWLER_FLAG_TRICKY_FLEE    0x200 /* flee when Tricky closes in; random re-dive */
#define WMWALLCRAWLER_FLAG_ATTACK_MOVE    0x400 /* lunge (anim move 2) when close */

#define WMWALLCRAWLER_MSG_PLAYER_BURST 0x60004 /* knock the player back with a burst hit */

/* state->mode */
enum
{
    WMWALLCRAWLER_MODE_IDLE = 0,    /* perched at spawn height */
    WMWALLCRAWLER_MODE_DESCEND = 1, /* dropping to home height */
    WMWALLCRAWLER_MODE_CHASE = 3,   /* tracking the target along the surface */
    WMWALLCRAWLER_MODE_FLEE = 5,    /* reversed away from the target, life timer running */
    WMWALLCRAWLER_MODE_DIE = 6      /* death anim, then free/hide */
};

extern f32 gWallCrawlerSpeedCap;
extern u8 gWallCrawlerHitCount;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E5FB0 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E5FB4 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E5FB8 = 100000.0f;
__declspec(section ".sdata2") f32 lbl_803E5FBC = 10000.0f;
__declspec(section ".sdata2") f32 lbl_803E5FC0 = 0.1f;
__declspec(section ".sdata2") f32 lbl_803E5FC4 = 0.4f;
__declspec(section ".sdata2") f32 lbl_803E5FC8 = 0.95f;
__declspec(section ".sdata2") f32 lbl_803E5FCC = 0.01f;
__declspec(section ".sdata2") f32 lbl_803E5FD0 = 1000.0f;
__declspec(section ".sdata2") f32 lbl_803E5FD4 = 30.0f;
__declspec(section ".sdata2") f32 lbl_803E5FD8 = 0.25f;
__declspec(section ".sdata2") f32 lbl_803E5FDC = -0.065f;
__declspec(section ".sdata2") f32 lbl_803E5FE0 = -1.0f;
__declspec(section ".sdata2") f32 lbl_803E5FE4 = -10.0f;
__declspec(section ".sdata2") f32 lbl_803E5FE8 = -0.1f;
__declspec(section ".sdata2") f32 lbl_803E5FEC = 2.0f;
__declspec(section ".sdata2") f32 lbl_803E5FF0 = 300.0f;
__declspec(section ".sdata2") f32 lbl_803E5FF4 = 15.0f;
__declspec(section ".sdata2") f32 lbl_803E5FF8 = 13.0f;
__declspec(section ".sdata2") f32 lbl_803E5FFC = 50.0f;
__declspec(section ".sdata2") f32 lbl_803E6000 = 0.3f;
__declspec(section ".sdata2") f32 lbl_803E6004 = 0.7f;
__declspec(section ".sdata2") f32 lbl_803E6008 = 26.0f;
__declspec(section ".sdata2") f32 lbl_803E600C = 8.0f;
__declspec(section ".sdata2") f32 lbl_803E6010 = 0.065f;
__declspec(section ".sdata2") f32 lbl_803E6014 = 0.03f;
__declspec(section ".sdata2") f32 lbl_803E6018 = -0.01f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E601C = 0.0f;
#pragma explicit_zero_data off
extern u16 gWallCrawlerVariantFlags[];
extern u8 gWallCrawlerPointCollision[];
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

int wmwallcrawler_animEventCallback(GameObject* obj)
{
    ((WmwallcrawlerState*)obj->extra)->mode = WMWALLCRAWLER_MODE_DESCEND;
    return 0;
}

/* dont_inline: defined before its update call sites (address order),
   but the retail unit keeps both bls. No same-TU callees, so the wrap
   is safe (see the dont_inline CAUTION in the playbook). */
#pragma dont_inline on
void wmwallcrawler_alignToFloorNormal(GameObject* obj, TrackGroundHit* floorHit)
{
    WcXf mtx;
    f32 in[3];
    u16 ang, ang2;
    in[0] = floorHit->normalX;
    in[1] = floorHit->normalY;
    in[2] = floorHit->normalZ;
    mtx.mc = lbl_803E5FB0;
    mtx.m10 = lbl_803E5FB0;
    mtx.m14 = lbl_803E5FB0;
    mtx.m8 = lbl_803E5FB4;
    mtx.r2 = 0;
    mtx.r1 = 0;
    mtx.r0 = obj->anim.rotX;
    vecRotateZXY(&mtx.r0, in);
    ang = getAngle(in[0], in[1]);
    ang2 = getAngle(in[2], in[1]);
    obj->anim.rotY = ang2;
    obj->anim.rotZ = ang;
}
#pragma dont_inline reset

int wmwallcrawler_getExtraSize(void)
{
    return sizeof(WmwallcrawlerState);
}

int wmwallcrawler_getObjectTypeId(void)
{
    return 0x0;
}

void wmwallcrawler_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, WMWALLCRAWLER_OBJGROUP);
}

void wmwallcrawler_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 vis)
{
    ObjAnimComponent* objAnim = &(obj)->anim;
    WmwallcrawlerState* state = obj->extra;
    if ((state->flags & WMWALLCRAWLER_FLAG_FADE_IN) != 0 && objAnim->alpha < 0xff)
    {
        if (objAnim->alpha > 0xff - framesThisStep)
        {
            objAnim->alpha = 0xff;
            state->flags &= ~WMWALLCRAWLER_FLAG_FADE_IN;
        }
        else
        {
            objAnim->alpha += framesThisStep;
        }
    }
    if (vis != 0 && state->despawnTimer == 0)
    {
        objRenderModelAndHitVolumesFwdLegacy(obj, p2, p3, p4, p5, lbl_803E5FB4); /* 1.0f */
    }
}

void wmwallcrawler_hitDetect(GameObject* obj)
{
    WmwallcrawlerState* state = (obj)->extra;
    f32 stk = lbl_803E5FB8;
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
    {
        if ((state->flags & WMWALLCRAWLER_FLAG_DEATH_ANIM) != 0)
        {
            state->mode = WMWALLCRAWLER_MODE_DIE;
        }
        else if (*(void**)(*(int*)&(obj)->anim.placementData + 0x14) == NULL)
        {
            ObjHits_DisableObject((u32)obj);
            Obj_FreeObject(obj);
        }
        else
        {
            Obj_RemoveFromUpdateList((u8*)obj);
            ObjHits_DisableObject((u32)obj);
            ObjGroup_RemoveObject((int)obj, WMWALLCRAWLER_OBJGROUP);
            (obj)->anim.flags = (obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
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
            target = ObjGroup_FindNearestObject(WMWALLCRAWLER_TARGET_OBJGROUP, (int)obj, &stk);
        }
        ObjHits_RecordObjectHit((int)target, (int)obj, 0xb, 1, 0);
        state->mode = WMWALLCRAWLER_MODE_DIE;
        ((WcHitBits*)&state->hitBits)->hit = 0;
    }
}

void wmwallcrawler_update(GameObject* obj)
{
    WmwallcrawlerState* state;
    int bestIdx;
    u32 ob;
    u32 player;
    f32 speed;
    int k;
    int hitCount;
    int idx;
    u32 tricky;
    u8 sum;
    int ang;
    f32 dist;
    f32 sq;
    s8 mode;
    TrackGroundHit** list;
    f32 best;
    f32 d;
    f32 dy;
    f32 dz;

    ob = (u32)obj;
    state = ((GameObject*)ob)->extra;
    bestIdx = 0;
    speed = lbl_803E5FB4;
    sum = 0;
    list = 0;
    best = lbl_803E5FBC;
    player = (state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0
                 ? (u32)Obj_GetPlayerObject()
                 : ObjGroup_FindNearestObject(WMWALLCRAWLER_TARGET_OBJGROUP, ob, &best);
    if (player != 0)
    {
        sq = mainGetBit(0x789);
        gWallCrawlerSpeedCap = lbl_803E5FC0 * sq + lbl_803E5FC0;
        if (state->mode == WMWALLCRAWLER_MODE_DIE)
        {
            ((GameObject*)ob)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            if (((GameObject*)ob)->anim.currentMove != 1)
            {
                ObjAnim_SetCurrentMove(ob, 1, lbl_803E5FB0, 0);
                Sfx_PlayFromObject(ob, SFXTRIG_id_73);
            }
            if (((GameObject*)ob)->anim.currentMoveProgress > lbl_803E5FC4)
            {
                ((GameObject*)ob)->anim.rootMotionScale = ((GameObject*)ob)->anim.rootMotionScale * lbl_803E5FC8;
            }
            if (ObjAnim_AdvanceCurrentMove(ob, lbl_803E5FCC, framesThisStep, NULL) !=
                0)
            {
                if (state->counterGameBit != 0 && state->counterGameBit != -1)
                {
                    mainSetBits(state->counterGameBit,
                                mainGetBit(state->counterGameBit) + 1);
                }
                if (*(void**)(*(int*)&((GameObject*)ob)->anim.placementData + 0x14) == 0)
                {
                    ObjHits_DisableObject((u32)ob);
                    Obj_FreeObject((GameObject*)ob);
                }
                else
                {
                    Obj_RemoveFromUpdateList((u8*)ob);
                    ObjHits_DisableObject((u32)ob);
                    ObjGroup_RemoveObject(ob, WMWALLCRAWLER_OBJGROUP);
                    ((GameObject*)ob)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
            }
        }
        else
        {
            if ((state->flags & WMWALLCRAWLER_FLAG_TIMED_EXPLODE) != 0)
            {
                if (timerCountDown((f32*)&state->explodeTimer) != 0)
                {
                    for (k = 0; k < 0x1e; k++)
                    {
                        (*gPartfxInterface)->spawnObject((void*)ob, WMWALLCRAWLER_PARTFX, NULL, 0, -1, NULL);
                    }
                    s16toFloat((f32*)&state->despawnTimer, 100);
                    return;
                }
                if (timerCountDown((f32*)&state->despawnTimer) != 0)
                {
                    ((GameObject*)ob)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                    if (*(void**)(*(int*)&((GameObject*)ob)->anim.placementData + 0x14) == 0)
                    {
                        ObjHits_DisableObject((u32)ob);
                        Obj_FreeObject((GameObject*)ob);
                    }
                    else
                    {
                        Obj_RemoveFromUpdateList((u8*)ob);
                        ObjHits_DisableObject((u32)ob);
                        ObjGroup_RemoveObject(ob, WMWALLCRAWLER_OBJGROUP);
                        ((GameObject*)ob)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    }
                    return;
                }
            }
            for (k = 0; k < 6; k++)
            {
                sum += mainGetBit(k + 0x2aa);
            }
            if (sum >= 6)
            {
                if (*(void**)(*(int*)&((GameObject*)ob)->anim.placementData + 0x14) == 0)
                {
                    ObjHits_DisableObject((u32)ob);
                    Obj_FreeObject((GameObject*)ob);
                }
                else
                {
                    Obj_RemoveFromUpdateList((u8*)ob);
                    ObjHits_DisableObject((u32)ob);
                    ObjGroup_RemoveObject(ob, WMWALLCRAWLER_OBJGROUP);
                    ((GameObject*)ob)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                }
            }
            else
            {
                if (fn_80080150((const f32*)&state->attackTimer) != 0)
                {
                    timerCountDown((f32*)&state->attackTimer);
                }
                else
                {
                    mode = state->mode;
                    if ((mode == WMWALLCRAWLER_MODE_CHASE || mode == WMWALLCRAWLER_MODE_DESCEND ||
                         mode == WMWALLCRAWLER_MODE_FLEE) &&
                        (state->flags & WMWALLCRAWLER_FLAG_NO_RETREAT) == 0)
                    {
                        if (mode == WMWALLCRAWLER_MODE_FLEE)
                        {
                            if (lbl_803E5FD0 > lbl_803E5FD4 + state->fleeChaseThreshold)
                            {
                                state->mode = WMWALLCRAWLER_MODE_CHASE;
                                state->attackTimer = 0x14;
                            }
                        }
                        else if (lbl_803E5FD0 < state->fleeChaseThreshold)
                        {
                            state->lifeTimer -= framesThisStep;
                            if (randFn_80080100(0x32) != 0)
                            {
                                Sfx_PlayFromObject(ob, SFXTRIG_id_74);
                            }
                            if (state->lifeTimer <= 0)
                            {
                                if ((state->flags & WMWALLCRAWLER_FLAG_DEATH_ANIM) != 0)
                                {
                                    state->mode = WMWALLCRAWLER_MODE_DIE;
                                }
                                else if (*(void**)(*(int*)&((GameObject*)ob)->anim.placementData + 0x14) == 0)
                                {
                                    ObjHits_DisableObject((u32)ob);
                                    Obj_FreeObject((GameObject*)ob);
                                }
                                else
                                {
                                    Obj_RemoveFromUpdateList((u8*)ob);
                                    ObjHits_DisableObject((u32)ob);
                                    ObjGroup_RemoveObject(ob, WMWALLCRAWLER_OBJGROUP);
                                    ((GameObject*)ob)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                                }
                                return;
                            }
                            if (state->mode != WMWALLCRAWLER_MODE_FLEE)
                            {
                                Sfx_StopObjectChannel(ob, 0x10);
                                state->mode = WMWALLCRAWLER_MODE_FLEE;
                                ((GameObject*)ob)->anim.velocityX =
                                    -((GameObject*)ob)->anim.velocityX * (d = lbl_803E5FD8);
                                ((GameObject*)ob)->anim.velocityZ = -((GameObject*)ob)->anim.velocityZ * d;
                            }
                        }
                    }
                    if ((state->flags & WMWALLCRAWLER_FLAG_TRICKY_FLEE) != 0 &&
                        state->mode != WMWALLCRAWLER_MODE_FLEE &&
                        (tricky = (u32)getTrickyObject()) != 0 &&
                        Vec_distance((void*)(ob + 0x18), (void*)(tricky + 0x18)) < lbl_803E5FD4 &&
                        (**(u8(**)(int))(*(int*)(*(int*)(tricky + 0x68)) + 0x44))(tricky) != 0)
                    {
                        state->mode = WMWALLCRAWLER_MODE_FLEE;
                        Sfx_PlayFromObject(ob, SFXTRIG_id_74);
                    }
                    if (state->mode == WMWALLCRAWLER_MODE_FLEE)
                    {
                        if ((state->flags & WMWALLCRAWLER_FLAG_PATH_CONTROL) != 0)
                        {
                            (*gPathControlInterface)->update((void*)ob, state, timeDelta);
                            (*gPathControlInterface)->apply((void*)ob, state);
                            (*gPathControlInterface)->advance((void*)ob, state, timeDelta);
                        }
                        sq = ((GameObject*)ob)->anim.velocityX * ((GameObject*)ob)->anim.velocityX +
                             ((GameObject*)ob)->anim.velocityZ * ((GameObject*)ob)->anim.velocityZ;
                        if (lbl_803E5FB0 != sq)
                        {
                            speed = sqrtf(sq);
                        }
                        state->animSpeed = lbl_803E5FDC * speed;
                        ObjAnim_AdvanceCurrentMove(
                            ob, state->animSpeed, framesThisStep, NULL);
                        ((GameObject*)ob)->anim.localPosX =
                            ((GameObject*)ob)->anim.velocityX * timeDelta + ((GameObject*)ob)->anim.localPosX;
                        ((GameObject*)ob)->anim.localPosZ =
                            ((GameObject*)ob)->anim.velocityZ * timeDelta + ((GameObject*)ob)->anim.localPosZ;
                        state->lifeTimer -= framesThisStep;
                        if ((state->flags & WMWALLCRAWLER_FLAG_FLOOR_SNAP) != 0)
                        {
                            best = lbl_803E5FBC;
                            hitCount = hitDetectFn_80065e50((GameObject*)ob, ((GameObject*)ob)->anim.localPosX,
                                                            ((GameObject*)ob)->anim.localPosY,
                                                            ((GameObject*)ob)->anim.localPosZ, &list, 0, 0);
                            idx = 0;
                            for (k = 0; k < hitCount; k++)
                            {
                                d = list[idx]->height - ((GameObject*)ob)->anim.localPosY;
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
                                ((GameObject*)ob)->anim.localPosY = list[bestIdx]->height;
                                wmwallcrawler_alignToFloorNormal((GameObject*)(ob), list[bestIdx]);
                            }
                            else
                            {
                                ((GameObject*)ob)->anim.localPosY = state->homeY;
                            }
                        }
                        else
                        {
                            ((GameObject*)ob)->anim.localPosY = state->homeY;
                        }
                        if ((state->flags & WMWALLCRAWLER_FLAG_NO_RETREAT) == 0 &&
                            state->lifeTimer <= 0)
                        {
                            if ((state->flags & WMWALLCRAWLER_FLAG_DEATH_ANIM) != 0)
                            {
                                state->mode = WMWALLCRAWLER_MODE_DIE;
                            }
                            else
                            {
                                state->mode = WMWALLCRAWLER_MODE_IDLE;
                                Sfx_StopObjectChannel(ob, 0x18);
                                ((GameObject*)ob)->anim.localPosX = state->homeX;
                                ((GameObject*)ob)->anim.localPosY =
                                    state->homeY + (f32)state->heightOffset;
                                ((GameObject*)ob)->anim.localPosZ = state->homeZ;
                            }
                        }
                        else if ((state->flags & WMWALLCRAWLER_FLAG_TRICKY_FLEE) != 0 &&
                                 (int)randomGetRange(0, 0x14) == 0)
                        {
                            state->mode = WMWALLCRAWLER_MODE_CHASE;
                            s16toFloat((f32*)&state->attackTimer,
                                       (s16)(randomGetRange(0, 0x14) + 0x32));
                        }
                    }
                    else
                    {
                        dist = Vec_xzDistance((f32*)(player + 0x18), (f32*)(ob + 0x18));
                        if (dist < state->triggerRadius || mainGetBit(0x1d9) != 0)
                        {
                            mode = state->mode;
                            if (mode == WMWALLCRAWLER_MODE_IDLE)
                            {
                                state->mode = WMWALLCRAWLER_MODE_DESCEND;
                                s16toFloat((f32*)&state->attackTimer, 2);
                                ((GameObject*)ob)->anim.rotZ = 0;
                            }
                            else if (mode == WMWALLCRAWLER_MODE_DESCEND)
                            {
                                if (((GameObject*)ob)->anim.velocityY > lbl_803E5FE4)
                                {
                                    ((GameObject*)ob)->anim.velocityY =
                                        lbl_803E5FE8 * timeDelta + ((GameObject*)ob)->anim.velocityY;
                                }
                                if (((GameObject*)ob)->anim.localPosY < state->homeY)
                                {
                                    ((GameObject*)ob)->anim.localPosY = state->homeY;
                                    ((GameObject*)ob)->anim.velocityY = lbl_803E5FB0;
                                    state->mode = WMWALLCRAWLER_MODE_CHASE;
                                    s16toFloat((f32*)&state->attackTimer,
                                               (s16)(randomGetRange(0, 0x14) + 0x32));
                                    state->triggerRadius =
                                        state->triggerRadius * lbl_803E5FEC;
                                    ObjAnim_SetCurrentMove(ob, 0, lbl_803E5FB0, 0);
                                }
                            }
                            else if (mode == WMWALLCRAWLER_MODE_CHASE)
                            {
                                Sfx_PlayFromObject(ob, SFXTRIG_id_47);
                                if ((state->flags & WMWALLCRAWLER_FLAG_PATH_CONTROL) != 0)
                                {
                                    (*gPathControlInterface)->update((void*)ob, state, timeDelta);
                                    (*gPathControlInterface)->apply((void*)ob, state);
                                    (*gPathControlInterface)->advance((void*)ob, state, timeDelta);
                                }
                                if ((state->flags & WMWALLCRAWLER_FLAG_FLOOR_SNAP) != 0)
                                {
                                    best = lbl_803E5FBC;
                                    hitCount = hitDetectFn_80065e50((GameObject*)ob, ((GameObject*)ob)->anim.localPosX,
                                                                    ((GameObject*)ob)->anim.localPosY,
                                                                    ((GameObject*)ob)->anim.localPosZ, &list, 0, 0);
                                    idx = 0;
                                    for (k = 0; k < hitCount; k++)
                                    {
                                        d = list[idx]->height - ((GameObject*)ob)->anim.localPosY;
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
                                        ((GameObject*)ob)->anim.localPosY = list[bestIdx]->height;
                                        wmwallcrawler_alignToFloorNormal((GameObject*)(ob), list[bestIdx]);
                                    }
                                    else
                                    {
                                        ((GameObject*)ob)->anim.localPosY = state->homeY;
                                    }
                                }
                                else
                                {
                                    ((GameObject*)ob)->anim.localPosY = state->homeY;
                                }
                                dy = ((GameObject*)player)->anim.localPosY - ((GameObject*)ob)->anim.localPosY;
                                dz = ((GameObject*)player)->anim.localPosZ - ((GameObject*)ob)->anim.localPosZ;
                                sq = (((GameObject*)player)->anim.localPosX - ((GameObject*)ob)->anim.localPosX) /
                                     (d = lbl_803E5FF0);
                                ((GameObject*)ob)->anim.velocityX = sq * timeDelta;
                                sq = dy / d;
                                ((GameObject*)ob)->anim.velocityY = sq * timeDelta;
                                sq = dz / d;
                                ((GameObject*)ob)->anim.velocityZ = sq * timeDelta;
                                if ((state->flags & WMWALLCRAWLER_FLAG_CLAMP_SPEED) != 0 &&
                                    sqrtf(((GameObject*)ob)->anim.velocityZ * ((GameObject*)ob)->anim.velocityZ +
                                          (((GameObject*)ob)->anim.velocityX * ((GameObject*)ob)->anim.velocityX +
                                           ((GameObject*)ob)->anim.velocityY * ((GameObject*)ob)->anim.velocityY)) >
                                        gWallCrawlerSpeedCap)
                                {
                                    Vec3_Normalize((f32*)(ob + 0x24));
                                    ((GameObject*)ob)->anim.velocityX =
                                        ((GameObject*)ob)->anim.velocityX * (timeDelta * gWallCrawlerSpeedCap);
                                    ((GameObject*)ob)->anim.velocityY =
                                        ((GameObject*)ob)->anim.velocityY * (timeDelta * gWallCrawlerSpeedCap);
                                    ((GameObject*)ob)->anim.velocityZ =
                                        ((GameObject*)ob)->anim.velocityZ * (timeDelta * gWallCrawlerSpeedCap);
                                }
                                if (((GameObject*)ob)->anim.currentMove == 0 &&
                                    (state->flags & WMWALLCRAWLER_FLAG_ATTACK_MOVE) != 0 &&
                                    dist < lbl_803E5FF4)
                                {
                                    ObjAnim_SetCurrentMove(ob, 2, lbl_803E5FB0, 0);
                                }
                                if (dist < lbl_803E5FF8 ||
                                    ((state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) != 0 &&
                                     ((((ObjHitsPriorityState*)((GameObject*)ob)->anim.hitReactState)->flags & 8) !=
                                      0) &&
                                     dist < lbl_803E5FFC))
                                {
                                    gWallCrawlerHitCount += 1;
                                    if (((GameObject*)ob)->anim.currentMove == 2 &&
                                        ((GameObject*)ob)->anim.currentMoveProgress > lbl_803E6000 &&
                                        ((GameObject*)ob)->anim.currentMoveProgress < lbl_803E6004)
                                    {
                                        ObjMsg_SendToObject((void*)player, WMWALLCRAWLER_MSG_PLAYER_BURST, (void*)ob,
                                                            1);
                                        gWallCrawlerHitCount = 0;
                                    }
                                    if (mainGetBit(0x1d9) != 0)
                                    {
                                        gWallCrawlerHitCount = 0;
                                    }
                                    else if (gWallCrawlerHitCount >= 3 || ((state->flags &
                                                                            WMWALLCRAWLER_FLAG_TARGET_NEAREST) != 0 &&
                                                                           gWallCrawlerHitCount >= 3))
                                    {
                                        Sfx_PlayFromObject(ob, SFXTRIG_id_75);
                                        if ((state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0)
                                        {
                                            ObjMsg_SendToObject((void*)player, WMWALLCRAWLER_MSG_PLAYER_BURST,
                                                                (void*)ob, 1);
                                        }
                                        else
                                        {
                                            ((WcHitBits*)&state->hitBits)->hit = 1;
                                        }
                                        gWallCrawlerHitCount = 0;
                                    }
                                    if ((state->flags & WMWALLCRAWLER_FLAG_TARGET_NEAREST) == 0)
                                    {
                                        d = lbl_803E6008;
                                        ((GameObject*)ob)->anim.localPosX =
                                            d * -((GameObject*)ob)->anim.velocityX + ((GameObject*)ob)->anim.localPosX;
                                        ((GameObject*)ob)->anim.localPosZ =
                                            d * -((GameObject*)ob)->anim.velocityZ + ((GameObject*)ob)->anim.localPosZ;
                                    }
                                    else
                                    {
                                        d = lbl_803E600C;
                                        ((GameObject*)ob)->anim.localPosX =
                                            d * -((GameObject*)ob)->anim.velocityX + ((GameObject*)ob)->anim.localPosX;
                                        ((GameObject*)ob)->anim.localPosZ =
                                            d * -((GameObject*)ob)->anim.velocityZ + ((GameObject*)ob)->anim.localPosZ;
                                    }
                                    s16toFloat((f32*)&state->attackTimer,
                                               (s16)(randomGetRange(0, 0x14) + 100));
                                }
                                ang =
                                    getAngle(((GameObject*)player)->anim.localPosX - ((GameObject*)ob)->anim.localPosX,
                                             ((GameObject*)player)->anim.localPosZ - ((GameObject*)ob)->anim.localPosZ);
                                ((GameObject*)ob)->anim.rotX = ang + 0x7fff;
                                sq = ((GameObject*)ob)->anim.velocityX * ((GameObject*)ob)->anim.velocityX +
                                     ((GameObject*)ob)->anim.velocityZ * ((GameObject*)ob)->anim.velocityZ;
                                if (lbl_803E5FB0 != sq)
                                {
                                    speed = sqrtf(sq);
                                }
                                switch (((GameObject*)ob)->anim.currentMove)
                                {
                                case 0:
                                    state->animSpeed = lbl_803E6010 * speed;
                                    break;
                                case 2:
                                    state->animSpeed = lbl_803E6014;
                                    break;
                                case 1:
                                    state->animSpeed = lbl_803E5FCC;
                                    break;
                                }
                                if (ObjAnim_AdvanceCurrentMove(
                                        ob, state->animSpeed, framesThisStep, NULL) != 0 &&
                                    ((GameObject*)ob)->anim.currentMove != 0)
                                {
                                    ObjAnim_SetCurrentMove(ob, 0, lbl_803E5FB0, 0);
                                }
                                ((GameObject*)ob)->anim.localPosX =
                                    ((GameObject*)ob)->anim.velocityX * timeDelta + ((GameObject*)ob)->anim.localPosX;
                                ((GameObject*)ob)->anim.localPosZ =
                                    ((GameObject*)ob)->anim.velocityZ * timeDelta + ((GameObject*)ob)->anim.localPosZ;
                            }
                        }
                        else if (state->mode == WMWALLCRAWLER_MODE_DESCEND)
                        {
                            if (((GameObject*)ob)->anim.velocityY > lbl_803E5FE0)
                            {
                                ((GameObject*)ob)->anim.velocityY =
                                    lbl_803E6018 * timeDelta + ((GameObject*)ob)->anim.velocityY;
                            }
                            if (((GameObject*)ob)->anim.localPosY < state->homeY)
                            {
                                ((GameObject*)ob)->anim.localPosY = state->homeY;
                                ((GameObject*)ob)->anim.velocityY = lbl_803E5FB0;
                                state->mode = WMWALLCRAWLER_MODE_CHASE;
                                s16toFloat((f32*)&state->attackTimer,
                                           (s16)(randomGetRange(0, 0x14) + 0x32));
                                state->triggerRadius =
                                    state->triggerRadius * lbl_803E5FEC;
                                ObjAnim_SetCurrentMove(ob, 0, lbl_803E5FB0, 0);
                            }
                            ((GameObject*)ob)->anim.localPosY =
                                ((GameObject*)ob)->anim.velocityY * timeDelta + ((GameObject*)ob)->anim.localPosY;
                        }
                        if (state->mode == WMWALLCRAWLER_MODE_IDLE)
                        {
                            ((GameObject*)ob)->anim.localPosY =
                                ((GameObject*)ob)->anim.velocityY * timeDelta + ((GameObject*)ob)->anim.localPosY;
                        }
                        if (randFn_80080100(0x32) != 0)
                        {
                            Sfx_PlayFromObject(ob, SFXTRIG_id_76);
                        }
                    }
                }
            }
        }
    }
}

void wmwallcrawler_init(GameObject* obj, WmwallcrawlerMapData* mapData)
{
    ObjAnimComponent* objAnim = &(obj)->anim;
    WmwallcrawlerState* state = (obj)->extra;
    u16 flags;
    ObjGroup_AddObject((int)obj, WMWALLCRAWLER_OBJGROUP);
    (obj)->anim.rotX = (s16)(mapData->rotXByte << 8);
    ObjMsg_AllocQueue(obj, 2);
    state->homeX = mapData->base.posX;
    state->homeY = mapData->base.posY;
    state->homeZ = mapData->base.posZ;
    state->triggerRadius = (f32)(int)mapData->triggerRadius;
    state->variant = mapData->variant;
    state->flags = gWallCrawlerVariantFlags[state->variant];
    storeZeroToFloatParam((f32*)&state->explodeTimer);
    storeZeroToFloatParam((f32*)&state->despawnTimer);
    storeZeroToFloatParam((f32*)&state->attackTimer);
    flags = state->flags;
    if ((flags & WMWALLCRAWLER_FLAG_START_ACTIVE) != 0)
    {
        (obj)->anim.rotZ = 0;
        state->mode = WMWALLCRAWLER_MODE_DESCEND;
    }
    else if ((flags & WMWALLCRAWLER_FLAG_TIMED_EXPLODE) != 0)
    {
        s16toFloat((f32*)&state->explodeTimer, 0x4b0);
        state->triggerRadius = lbl_803E6030;
        (obj)->anim.rotZ = 0;
        state->mode = WMWALLCRAWLER_MODE_DESCEND;
    }
    else
    {
        s16toFloat((f32*)&state->attackTimer, 0x190);
        (obj)->anim.rotZ = -0x7fff;
        state->mode = WMWALLCRAWLER_MODE_IDLE;
    }
    if ((state->flags & WMWALLCRAWLER_FLAG_FADE_IN) != 0)
    {
        objAnim->alpha = 0;
    }
    state->animSpeed = lbl_803E5FB0;
    state->heightOffset = mapData->heightOffset;
    (obj)->anim.localPosY = mapData->base.posY + (f32)(int)state->heightOffset;
    state->lifeTimer = (s16)(randomGetRange(0, 0x50) + 0x190);
    state->fleeChaseThreshold = lbl_803E6034;
    state->counterGameBit = mapData->counterGameBit;
    if ((state->flags & WMWALLCRAWLER_FLAG_PATH_CONTROL) != 0)
    {
        state->pathState[0x25b] = 1;
        (*gPathControlInterface)->init((void*)state, 0, 0, 1);
        (*gPathControlInterface)
            ->setLocalPointCollision((void*)state, 1, gWallCrawlerPointCollision, sWallCrawlerCollisionBone, 4);
        (*gPathControlInterface)->attachObject((void*)obj, state);
        *(u32*)state |= 0x40008;
    }
    (obj)->animEventCallback = wmwallcrawler_animEventCallback;
    ObjHits_EnableObject((u32)obj);
    ObjHits_SyncObjectPositionIfDirty((GameObject*)obj);
}

void wmwallcrawler_release(void)
{
}

void wmwallcrawler_initialise(void)
{
}

u16 gWallCrawlerVariantFlags[8] = {0x0000, 0x0002, 0x0004, 0x0001, 0x000C, 0x03F7, 0x0167, 0x050C};
u8 gWallCrawlerPointCollision[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/*__DATA_EXTERNS__*/
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* gWM_WallCrawlerObjDescriptor[15] = {(void*)0x00000000,
                                          (void*)0x00000000,
                                          (void*)0x00000000,
                                          (void*)0x00090000,
                                          wmwallcrawler_initialise,
                                          wmwallcrawler_release,
                                          (void*)0x00000000,
                                          wmwallcrawler_init,
                                          wmwallcrawler_update,
                                          wmwallcrawler_hitDetect,
                                          wmwallcrawler_render,
                                          wmwallcrawler_free,
                                          wmwallcrawler_getObjectTypeId,
                                          wmwallcrawler_getExtraSize,
                                          (void*)0x00000000};
u8 lbl_80328E28[48] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

__declspec(section ".sdata2") f32 lbl_803E6030 = 100.0f;
__declspec(section ".sdata2") f32 lbl_803E6034 = 80.0f;
