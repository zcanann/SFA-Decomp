/*
 * drakordthornbush (DLL 0x24E) - the thorn/bramble hazard objects from the
 * Drakor boss arena. The object's anim seqId selects one of two variants:
 *   - THORNBUSH_SEQ_THORN (0x727): a thorn cluster that grows in, can be hit
 *     to spawn an explosion, and (when the placement carries no respawn data)
 *     frees itself.
 *   - THORNBUSH_SEQ_LIGHTNING (0x709): a lightning bramble that additionally
 *     drives an Obj_UpdateLightningCluster effect, plays lightning sfx, and
 *     damages the player on proximity.
 * Common behaviour: it grows from a placement-driven scale, registers a hit
 * sphere, counts down a regrow timer, and on death either respawns from the
 * placement's regrow value, frees itself, or hides + drops off the update
 * list. Lightning state holds an objCreateLight model light freed on object
 * free.
 *
 * This TU has no .data section; the ObjectDescriptor wiring these handlers is
 * defined in another DR DLL translation unit.
 */
#include "main/dll/DR/dll_80209FE0_shared.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_trigger_ids.h"

/* object def numbers selecting the two thornbush variants (anim.seqId) */
#define THORNBUSH_SEQ_LIGHTNING 0x709
#define THORNBUSH_SEQ_THORN     0x727

typedef struct DrakordThornbushPlacement
{
    u8 pad0[0x19 - 0x0];
    u8 spawnHealth;         /* 0x19: initial hit points */
    s16 regrowDelay;        /* 0x1A: frames before regrow (0 = no respawn) */
    s16 baseRadius;         /* 0x1C: base hit-sphere radius */
    u8 pad1E[0x20 - 0x1E];
} DrakordThornbushPlacement;

typedef struct DrakordThornbushState
{
    s32 health;            /* 0x00: hit points; 0 = dormant */
    u8 pad4[0x8 - 0x4];
    s32 lastHitObj;        /* 0x08: most recent attacker, debounces re-hits */
    f32 growth;            /* 0x0C: regrow timer / scale driver */
    f32 regrowTimer;       /* 0x10: hit/regrow countdown */
    u8 lightningCluster[0x64 - 0x14]; /* 0x14: Obj_UpdateLightningCluster data */
    s32 light;             /* 0x64: model light handle (lightning variant) */
    f32 lightScale;        /* 0x68: lightning scale, accumulates over time */
    void* hitTable;        /* 0x6C: hit-reaction table pointer */
    f32 baseScale;         /* 0x70: per-variant init scale constant */
    s32 radius;            /* 0x74 */
    u8 tail78[0x7c - 0x78]; /* 0x78: holds DrakorFlags byte at 0x79 */
} DrakordThornbushState;

STATIC_ASSERT(offsetof(DrakordThornbushPlacement, spawnHealth) == 0x19);
STATIC_ASSERT(offsetof(DrakordThornbushPlacement, regrowDelay) == 0x1A);
STATIC_ASSERT(offsetof(DrakordThornbushPlacement, baseRadius) == 0x1C);
STATIC_ASSERT(sizeof(DrakordThornbushPlacement) == 0x20);
STATIC_ASSERT(offsetof(DrakordThornbushState, regrowTimer) == 0x10);
STATIC_ASSERT(offsetof(DrakordThornbushState, light) == 0x64);
STATIC_ASSERT(offsetof(DrakordThornbushState, lightScale) == 0x68);
STATIC_ASSERT(offsetof(DrakordThornbushState, hitTable) == 0x6C);
STATIC_ASSERT(offsetof(DrakordThornbushState, baseScale) == 0x70);
STATIC_ASSERT(offsetof(DrakordThornbushState, radius) == 0x74);
STATIC_ASSERT(sizeof(DrakordThornbushState) == 0x7c);

int drakord_thornbush_getExtraSize(void)
{
    return 0x7c;
}

int drakord_thornbush_getObjectTypeId(void)
{
    return 0;
}

void drakord_thornbush_release(void)
{
}

void drakord_thornbush_initialise(void)
{
}

#pragma opt_common_subs off

void drakord_thornbush_free(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == THORNBUSH_SEQ_LIGHTNING)
    {
        ((void (*)(int, int, int, f32, int))Obj_UpdateLightningCluster)(obj, inner + 0x14, 3, lbl_803E6588, inner + 0x64);
    }
    if (*(void**)&((DrakordThornbushState*)inner)->light != NULL)
    {
        ModelLightStruct_free(((DrakordThornbushState*)inner)->light);
    }
}

void drakord_thornbush_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int*)&((GameObject*)p1)->extra;
    f32 v;
    if (((GameObject*)p1)->anim.seqId == THORNBUSH_SEQ_LIGHTNING)
    {
        v = ((DrakordThornbushState*)inner)->lightScale;
        if (v < lbl_803E6590)
        {
            v = gThornBushLightScaleMax;
        }
        ((void (*)(int, int, int, f32, int))Obj_UpdateLightningCluster)(p1, inner + 0x14, 3, v, inner + 0x64);
    }
    objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E6594);
}

void drakord_thornbush_update(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
    int setup2;
    if (fn_80080150((int)((char*)inner + 0xc)) != 0)
    {
        if (((DrakordThornbushState*)inner)->growth < (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius)
        {
            ObjHits_EnableObject(obj);
            ObjHitbox_SetSphereRadius(
                obj, (int)(lbl_803E65A8 + (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius - ((DrakordThornbushState
                    *)inner)->growth));
        }
        if (timerCountDown(&((DrakordThornbushState*)inner)->growth) != 0)
        {
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ((DrakorFlags*)((char*)inner + 0x79))->b80 = 1;
            if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xffffffff)
            {
                Obj_FreeObject(obj);
            }
        }
    }
    else
    {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_drak_pain2);
        if (((DrakorFlags*)((char*)inner + 0x79))->b80)
        {
            ((DrakorFlags*)((char*)inner + 0x79))->b80 = 0;
        }
        switch (((GameObject*)obj)->anim.seqId)
        {
        case THORNBUSH_SEQ_THORN:
            if (fn_802972A8((int)Obj_GetPlayerObject()) != NULL)
            {
                ObjHits_ClearHitVolumes(obj);
                ObjHits_EnableObject(obj);
            }
            else
            {
                ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
            }
            break;
        case THORNBUSH_SEQ_LIGHTNING:
            if (Vec_distance((int*)((char*)Obj_GetPlayerObject() + 0x18), (int*)&((GameObject*)obj)->anim.worldPosX) <
                (f32)(s32)(((DrakordThornbushPlacement*)setup)->baseRadius << 1))
            {
                ObjHits_RecordObjectHit((int)Obj_GetPlayerObject(), obj, 5, 1, 0);
            }
            break;
        }
        if (((DrakordThornbushState*)inner)->health == 0)
        {
            setup2 = *(int*)&((GameObject*)obj)->anim.placementData;
            ObjHits_EnableObject(obj);
            ((DrakordThornbushState*)inner)->health = ((DrakordThornbushPlacement*)setup2)->spawnHealth;
            ObjHitbox_SetSphereRadius(obj, (s16)((DrakordThornbushState*)inner)->radius);
        }
        if (((GameObject*)obj)->anim.seqId == THORNBUSH_SEQ_LIGHTNING)
        {
            if (((DrakordThornbushState*)inner)->lightScale < gThornBushLightScaleMax)
            {
                ((DrakordThornbushState*)inner)->lightScale = gThornBushLightScaleRate * (f32)(u32)
                framesThisStep + ((DrakordThornbushState*)inner)->lightScale;
                ((GameObject*)obj)->anim.rootMotionScale =
                    ((DrakordThornbushState*)inner)->lightScale *
                    (((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase *
                     (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius) /
                    lbl_803E65B0;
            }
        }
    }
}

void drakord_thornbush_hitDetect(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 hitPosZ;
    f32 hitPosY;
    f32 hitPosX;
    int damage;
    int hitObj;
    int destroyed;
    int hit;
    int setup;
    if (((DrakordThornbushState*)inner)->health != 0)
    {
        destroyed = timerCountDown((f32*)((char*)inner + 0x10));
        hit = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, 0, &damage, &hitPosX, &hitPosY, &hitPosZ);
        if (hit != 0)
        {
            if (((GameObject*)hitObj)->anim.seqId != 0x35f &&
                *(void**)&((DrakordThornbushState*)inner)->lastHitObj != (void*)hitObj &&
                arrayIndexOf(((DrakordThornbushState*)inner)->hitTable, 2, hit) != -1)
            {
                ((DrakordThornbushState*)inner)->lastHitObj = hitObj;
                Obj_SpawnHitLightAndFade(obj, &hitPosX, lbl_803E6598);
                ((DrakordThornbushState*)inner)->health -= damage;
                if (((DrakordThornbushState*)inner)->health <= 0)
                {
                    destroyed = 1;
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_wmap_nameoff_496);
                }
            }
        }
        else
        {
            ((DrakordThornbushState*)inner)->lastHitObj = 0;
        }
        if (destroyed != 0)
        {
            setup = *(int*)&((GameObject*)obj)->anim.placementData;
            ((DrakordThornbushState*)inner)->health = 0;
            switch (((GameObject*)obj)->anim.seqId)
            {
            case THORNBUSH_SEQ_THORN:
                spawnExplosion((int*)obj, (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius, 1, 0, 0, 0, 0, 1, 1);
                break;
            case THORNBUSH_SEQ_LIGHTNING:
                Sfx_PlayFromObject(obj, SFXTRIG_awghitobj16);
                spawnExplosion((int*)obj, (f32)(s32)(((DrakordThornbushState*)inner)->radius << 1), 1, 1, 1, 1, 0, 1,
                               0);
                ((void (*)(int, int, int, f32, int))Obj_UpdateLightningCluster)(obj, inner + 0x14, 3, lbl_803E6588, inner + 0x64);
                break;
            }
            if (((DrakordThornbushPlacement*)setup)->regrowDelay != 0)
            {
                s16toFloat((void*)&((DrakordThornbushState*)inner)->growth, ((DrakordThornbushPlacement*)setup)->regrowDelay);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject(obj);
            }
            else if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xffffffff)
            {
                Obj_FreeObject(obj);
            }
            else
            {
                Obj_RemoveFromUpdateList((int*)obj);
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}

void drakord_thornbush_init(int obj, u8* init)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    ((DrakordThornbushState*)inner)->health = 0;
    ObjHits_SetTargetMask(obj, 4);
    ((GameObject*)obj)->anim.rotY = (s16)((s8)init[0x18] << 8);
    if (*(u32*)&((ObjPlacement*)init)->mapId == 0xffffffff)
    {
        ((DrakorFlags*)((char*)inner + 0x79))->b80 = 1;
    }
    storeZeroToFloatParam(&((DrakordThornbushState*)inner)->growth);
    storeZeroToFloatParam((f32*)((char*)inner + 0x10));
    ((DrakordThornbushState*)inner)->lastHitObj = 0;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case THORNBUSH_SEQ_THORN:
        ((DrakordThornbushState*)inner)->hitTable = &gThornBushThornHitTable;
        ObjHitbox_SetSphereRadius(obj, ((DrakordThornbushPlacement*)init)->baseRadius);
        ((DrakordThornbushState*)inner)->radius = ((DrakordThornbushPlacement*)init)->baseRadius;
        ((DrakordThornbushState*)inner)->baseScale = lbl_803E65C0;
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * (f32)(s32)((DrakordThornbushPlacement*)init)->baseRadius /
            lbl_803E6590;
        break;
    case THORNBUSH_SEQ_LIGHTNING:
        ((DrakordThornbushState*)inner)->hitTable = &gThornBushLightningHitTable;
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * (f32)(s32)((DrakordThornbushPlacement*)init)->baseRadius /
            lbl_803E65C4;
        ObjHitbox_SetSphereRadius(obj, (s16)(((DrakordThornbushPlacement*)init)->baseRadius / 7));
        s16toFloat((f32*)((char*)inner + 0x10), gThornBushLightningTimerInit);
        ((DrakordThornbushState*)inner)->baseScale = lbl_803E65C8;
        ((DrakordThornbushState*)inner)->radius = ((DrakordThornbushPlacement*)init)->baseRadius / 5;
        ((DrakordThornbushState*)inner)->lightScale = lbl_803E6594;
        break;
    }
}

#pragma opt_common_subs reset
