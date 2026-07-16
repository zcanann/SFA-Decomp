/*
 * invhit (DLL 0xF1) - "invisible hit" volume objects of the pushable
 * effect family. One placement type drives several distinct hit-volume
 * behaviours selected by InvHitState.mode (def[0x1a], 0..7):
 *   0  proximity damage: scan the player (and Tricky) and bump the
 *      hit-priority counters once they fall inside unkF8 range.
 *   1  attach to an owner object's hit list (ObjList_ContainsObject).
 *   2  passive shape/radius hit volume.
 *   3  publish the object's world position to lbl_803AC780 while the
 *      player exists.
 *   4  homing/tethered projectile: ease toward the owner's target,
 *      clamp to a growing reach around an anchor, spawn fx, and snap to
 *      ground via hitDetectFn_80065e50.
 *   5  like 3 but gated on the player having a lock-on target.
 *   6  fixed primary-radius hit volume.
 *   7  self-free once the owner's hit list no longer references it.
 * InvHit_free releases the expgfx source for mode 4.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_descriptor.h"
#include "main/object_api.h"
#include "main/object_render_legacy.h"
#include "main/obj_list.h"
#include "main/dll/pushable.h"
#include "main/dll/player_target.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/track_dolphin_api.h"

typedef struct InvHitState
{
    f32 anchorX;
    f32 anchorZ;
    u8 mode;
} InvHitState;

typedef struct InvhitObjectDef
{
    u8 pad0[0x18];
    u8 radius;       /* 0x18: primaryRadius / unkF8 seed */
    u8 shapeFlags;   /* 0x19 */
    u8 mode;         /* 0x1a: InvHitState.mode selector */
    u8 pad1b[0x1C - 0x1B];
    void* anchorObj; /* 0x1c */
} InvhitObjectDef;

#define INVHIT_OBJFLAG_HIDDEN             0x4000
#define INVHIT_OBJFLAG_HITDETECT_DISABLED 0x2000

#define INVHIT_MODE_PROXIMITY_DAMAGE  0 /* scan player/Tricky, bump hit counters in range */
#define INVHIT_MODE_ATTACH            1 /* attach to owner's hit list */
#define INVHIT_MODE_PASSIVE_VOLUME    2 /* passive shape/radius hit volume */
#define INVHIT_MODE_PUBLISH_POS       3 /* publish world position while player exists */
#define INVHIT_MODE_HOMING_PROJECTILE 4 /* homing/tethered projectile toward owner target */
#define INVHIT_MODE_LOCKON_GATE       5 /* like publish, gated on player lock-on target */
#define INVHIT_MODE_FIXED_RADIUS      6 /* fixed primary-radius hit volume */
#define INVHIT_MODE_SELF_FREE         7 /* self-free once owner hit list drops it */

/* single-precision override for codegen */
f32 lbl_803AC780[4];

int InvHit_getExtraSize(void)
{
    return 0xc;
}
int InvHit_getObjectTypeId(void)
{
    return 0x0;
}
#pragma peephole off
#pragma scheduling off
void InvHit_free(GameObject* obj)
{
    char* inner = obj->extra;
    switch (((InvHitState*)inner)->mode)
    {
    case INVHIT_MODE_HOMING_PROJECTILE:
        (*gExpgfxInterface)->freeSource2((u32)obj);
        break;
    }
}
#pragma peephole on
void InvHit_render(int* obj, int a, int b, int c, int d)
{
    objRenderModelAndHitVolumes((int)obj, a, b, c, d, 1.0f);
}
#pragma scheduling on

void InvHit_hitDetect(void)
{
}

#pragma peephole off
#pragma scheduling off

void InvHit_init(int* obj, u8* def);
void InvHit_update(int* obj);
void InvHit_release(void);
void InvHit_initialise(void);

ObjectDescriptor gInvHitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)InvHit_initialise,
    (ObjectDescriptorCallback)InvHit_release,
    0,
    (ObjectDescriptorCallback)InvHit_init,
    (ObjectDescriptorCallback)InvHit_update,
    (ObjectDescriptorCallback)InvHit_hitDetect,
    (ObjectDescriptorCallback)InvHit_render,
    (ObjectDescriptorCallback)InvHit_free,
    (ObjectDescriptorCallback)InvHit_getObjectTypeId,
    InvHit_getExtraSize,
};

void InvHit_update(int* obj)
{
    InvHitState* state;
    char* targetObj;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
    switch (state->mode)
    {
    case INVHIT_MODE_PROXIMITY_DAMAGE:
    {
        GameObject* victim = Obj_GetPlayerObject();
        while (victim != NULL)
        {
            f32 dx = ((GameObject*)obj)->anim.localPosX - victim->anim.localPosX;
            f32 dy = ((GameObject*)obj)->anim.localPosY - victim->anim.localPosY;
            f32 dz = ((GameObject*)obj)->anim.localPosZ - victim->anim.localPosZ;
            f32 dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (dist < (f32)((GameObject*)obj)->unkF8)
            {
                u8* victimHits = *(u8**)&((GameObject*)victim)->anim.hitReactState;
                victimHits[0x71] += 1;
                ((ObjHitsPriorityState*)victimHits)->flags = ((ObjHitsPriorityState*)victimHits)->flags & ~1;
                (*(u8**)&((GameObject*)obj)->anim.hitReactState)[0x71] += 1;
            }
            if (victim->anim.classId == 1)
            {
                victim = getTrickyObject();
            }
            else
            {
                victim = NULL;
            }
        }
        break;
    }
    case INVHIT_MODE_PUBLISH_POS:
        if (Obj_GetPlayerObject() != NULL)
        {
            lbl_803AC780[0] = ((GameObject*)obj)->anim.worldPosX;
            lbl_803AC780[1] = ((GameObject*)obj)->anim.worldPosY;
            lbl_803AC780[2] = ((GameObject*)obj)->anim.worldPosZ;
        }
        break;
    case INVHIT_MODE_LOCKON_GATE:
    {
        void* pl = Obj_GetPlayerObject();
        u32 v = Player_GetTargetObject((int)pl);
        if (pl != NULL && v != 0)
        {
            lbl_803AC780[0] = ((GameObject*)obj)->anim.worldPosX;
            lbl_803AC780[1] = ((GameObject*)obj)->anim.worldPosY;
            lbl_803AC780[2] = ((GameObject*)obj)->anim.worldPosZ;
        }
        break;
    }
    case INVHIT_MODE_ATTACH:
        ObjList_ContainsObject(((GameObject*)obj)->unkF4);
        break;
    case INVHIT_MODE_SELF_FREE:
    {
        ObjHitsPriorityState* hitState = *(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState;
        char* ownerHitSlot;
        char* ownerHitState = *(char**)(((GameObject*)obj)->unkF4 + 0x54);
        int j;

        j = 0;
        ownerHitSlot = ownerHitState;
        for (; j < *(s8*)(ownerHitState + 0x71); j++)
        {
            if (*(int**)(ownerHitSlot + 0x7c) == obj)
            {
                hitState->flags = hitState->flags & ~1;
                Obj_FreeObject((GameObject*)obj);
            }
            ownerHitSlot += 4;
        }
        break;
    }
    case INVHIT_MODE_HOMING_PROJECTILE:
    {
        char* hitState = *(char**)&((GameObject*)obj)->anim.hitReactState;
        TrackGroundHit** hits[2];
        f32 dx2;
        f32 dz2;
        f32 reach;
        int cnt;
        f32 thr;
        int i;

        ((GameObject*)obj)->unkF8 -= framesThisStep;
        if (*(void**)&((ObjHitsPriorityState*)hitState)->lastHitObject != NULL)
        {
            ((ObjHitsPriorityState*)hitState)->flags = 0;
        }
        targetObj = *(char**)&((GameObject*)obj)->unkF4;
        if (targetObj != NULL)
        {
            f32 dx;
            f32 dz;
            f32 smoothTime;
            f32 qt;
            f32 dist;

            if (ObjList_ContainsObject((int)targetObj) == 0)
                break;
            dx = ((GameObject*)targetObj)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            dz = ((GameObject*)targetObj)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
            smoothTime = 48.0f;
            qt = dx / smoothTime;
            ((GameObject*)obj)->anim.localPosX = qt * timeDelta + ((GameObject*)obj)->anim.localPosX;
            qt = dz / smoothTime;
            ((GameObject*)obj)->anim.localPosZ = qt * timeDelta + ((GameObject*)obj)->anim.localPosZ;
            dx = ((GameObject*)targetObj)->anim.localPosX - state->anchorX;
            dz = ((GameObject*)targetObj)->anim.localPosZ - state->anchorZ;
            reach = 10.0f + sqrtf(dx * dx + dz * dz);
            dx2 = ((GameObject*)obj)->anim.localPosX - state->anchorX;
            dz2 = ((GameObject*)obj)->anim.localPosZ - state->anchorZ;
            dist = sqrtf(dx2 * dx2 + dz2 * dz2);
            if (dist > reach)
            {
                f32 r = reach / dist;
                dx2 = dx2 * r;
                dz2 = dz2 * r;
                ((GameObject*)obj)->anim.localPosX = state->anchorX + dx2;
                ((GameObject*)obj)->anim.localPosZ = state->anchorZ + dz2;
            }
            (*gPartfxInterface)->spawnObject(obj, 0x25, NULL, 0, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 0x56, NULL, 0, -1, NULL);
        }
        {
            s8 tmp =
                (s8)hitDetectFn_80065e50((GameObject*)obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                         ((GameObject*)obj)->anim.localPosZ, hits, 0, 0);
            i = 0;
            cnt = tmp;
        }
        thr = 20.0f;
        for (; i < cnt; i++)
        {
            f32 h = hits[0][i]->height;
            f32 oy = ((GameObject*)obj)->anim.localPosY;
            if (h < thr + oy && h > oy - thr)
            {
                ((GameObject*)obj)->anim.localPosY = h;
                i = cnt;
            }
        }
        break;
    }
    }
}

#pragma opt_common_subs off
void InvHit_init(int* obj, u8* def)
{
    InvHitState* state = ((GameObject*)obj)->extra;
    char* sub;

    state->mode = ((InvhitObjectDef*)def)->mode;
    sub = *(char**)&((GameObject*)obj)->anim.hitReactState;
    ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags & ~1;
    switch (state->mode)
    {
    case INVHIT_MODE_PROXIMITY_DAMAGE:
        ((GameObject*)obj)->unkF8 = ((InvhitObjectDef*)def)->radius;
        break;
    case INVHIT_MODE_FIXED_RADIUS:
        sub[0x62] = 1;
        ((ObjHitsPriorityState*)sub)->primaryRadius = 0x23;
        ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags | 0x45;
        sub[0x6e] = 0xb;
        sub[0x6f] = 1;
        sub[0xae] = 0;
        sub[0xaf] = 0;
        *(int*)&((ObjHitsPriorityState*)sub)->objectHitMask = 0x10;
        *(int*)&((ObjHitsPriorityState*)sub)->skeletonHitMask = 0x10;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case INVHIT_MODE_PUBLISH_POS:
        ((GameObject*)obj)->unkF8 = ((InvhitObjectDef*)def)->radius;
        ((GameObject*)obj)->unkF4 = 0;
        break;
    case INVHIT_MODE_LOCKON_GATE:
        ((GameObject*)obj)->unkF8 = ((InvhitObjectDef*)def)->radius;
        ((GameObject*)obj)->unkF4 = 0;
        break;
    case INVHIT_MODE_SELF_FREE:
        sub[0x62] = 1;
        ((ObjHitsPriorityState*)sub)->primaryRadius = ((InvhitObjectDef*)def)->radius;
        ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags | 0x45;
        sub[0xae] = 0;
        sub[0x6e] = 0xa;
        sub[0x6f] = 0;
        sub[0xaf] = 0;
        *(int*)&((ObjHitsPriorityState*)sub)->objectHitMask = 0x10;
        *(int*)&((ObjHitsPriorityState*)sub)->skeletonHitMask = 0x10;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case INVHIT_MODE_ATTACH:
        sub[0x62] = 1;
        ((ObjHitsPriorityState*)sub)->primaryRadius = ((InvhitObjectDef*)def)->radius;
        ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags | 0x45;
        sub[0xae] = 0;
        sub[0x6e] = 0xb;
        sub[0x6f] = 1;
        sub[0xaf] = 0;
        sub[0x6e] = 0x11;
        sub[0x6f] = 1;
        *(int*)&((ObjHitsPriorityState*)sub)->objectHitMask = 0x10;
        *(int*)&((ObjHitsPriorityState*)sub)->skeletonHitMask = 0x10;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case INVHIT_MODE_PASSIVE_VOLUME:
        ((ObjHitsPriorityState*)sub)->shapeFlags = ((InvhitObjectDef*)def)->shapeFlags;
        ((ObjHitsPriorityState*)sub)->primaryRadius = ((InvhitObjectDef*)def)->radius;
        ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags | 1;
        sub[0xae] = 0;
        sub[0xaf] = 0;
        sub[0x6a] = 0;
        sub[0x6b] = 0;
        break;
    case INVHIT_MODE_HOMING_PROJECTILE:
        sub[0x62] = 1;
        ((ObjHitsPriorityState*)sub)->primaryRadius = 0xa;
        ((ObjHitsPriorityState*)sub)->flags = 3;
        *(int*)&((ObjHitsPriorityState*)sub)->objectHitMask = 0x10;
        ((GameObject*)obj)->unkF8 = 0x78;
        {
            char* anchorObj = *(char**)&((InvhitObjectDef*)def)->anchorObj;
            if (anchorObj != NULL)
            {
                state->anchorX = ((GameObject*)anchorObj)->anim.localPosX;
                state->anchorZ = ((GameObject*)(*(char**)&((InvhitObjectDef*)def)->anchorObj))->anim.localPosZ;
            }
        }
        break;
    }
    ((GameObject*)obj)->objectFlags =
        ((GameObject*)obj)->objectFlags | (INVHIT_OBJFLAG_HIDDEN | INVHIT_OBJFLAG_HITDETECT_DISABLED);
}


#pragma opt_common_subs reset
#pragma peephole on
#pragma scheduling on

void InvHit_release(void)
{
}


void InvHit_initialise(void)
{
}
