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
 * invhit_free releases the expgfx source for mode 4.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/pushable.h"
#include "main/dll/player_target.h"
#include "main/engine_shared.h"

#define INVHIT_OBJFLAG_HIDDEN 0x4000
#define INVHIT_OBJFLAG_HITDETECT_DISABLED 0x2000

#define INVHIT_MODE_PROXIMITY_DAMAGE 0 /* scan player/Tricky, bump hit counters in range */
#define INVHIT_MODE_ATTACH 1           /* attach to owner's hit list */
#define INVHIT_MODE_PASSIVE_VOLUME 2   /* passive shape/radius hit volume */
#define INVHIT_MODE_PUBLISH_POS 3      /* publish world position while player exists */
#define INVHIT_MODE_HOMING_PROJECTILE 4 /* homing/tethered projectile toward owner target */
#define INVHIT_MODE_LOCKON_GATE 5      /* like publish, gated on player lock-on target */
#define INVHIT_MODE_FIXED_RADIUS 6     /* fixed primary-radius hit volume */
#define INVHIT_MODE_SELF_FREE 7        /* self-free once owner hit list drops it */

typedef struct InvHitState
{
    f32 anchorX;
    f32 anchorZ;
    u8 mode;
} InvHitState;

typedef struct InvhitObjectDef
{
    u8 pad0[0x1C - 0x0];
    void* anchorObj;
} InvhitObjectDef;

extern void Obj_FreeObject(int* obj);
extern int ObjList_ContainsObject(int obj);
extern f32 lbl_803E35E8;
extern void objRenderFn_8003b8f4(int* obj, int a, int b, int c, int d, f32 scale);

extern void* getTrickyObject(void);
 /* single-precision override for codegen */
extern f32 lbl_803AC780[];
extern s8 hitDetectFn_80065e50(int* obj, f32 x, f32 y, f32 z, f32*** list, int a, int b);
extern f32 lbl_803E35EC;
extern f32 lbl_803E35F0;
extern f32 lbl_803E35F4;

void invhit_hitDetect(void)
{
}

void invhit_release(void)
{
}

void invhit_initialise(void)
{
}

int invhit_getExtraSize(void) { return 0xc; }
int invhit_getObjectTypeId(void) { return 0x0; }

void invhit_render(int* obj, int a, int b, int c, int d) { objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E35E8); }

#pragma scheduling off
#pragma peephole off
void invhit_free(int obj)
{
    char* inner = ((GameObject*)obj)->extra;
    switch (((InvHitState*)inner)->mode)
    {
    case INVHIT_MODE_HOMING_PROJECTILE:
        (*gExpgfxInterface)->freeSource2((u32)obj);
        break;
    }
}

#pragma opt_common_subs off
void invhit_init(int* obj, u8* def)
{
    InvHitState* state = ((GameObject*)obj)->extra;
    char* sub;

    state->mode = def[0x1a];
    sub = *(char**)&((GameObject*)obj)->anim.hitReactState;
    ((ObjHitsPriorityState*)sub)->flags = ((ObjHitsPriorityState*)sub)->flags & ~1;
    switch (state->mode)
    {
    case INVHIT_MODE_PROXIMITY_DAMAGE:
        ((GameObject*)obj)->unkF8 = def[0x18];
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
        ((GameObject*)obj)->unkF8 = def[0x18];
        ((GameObject*)obj)->unkF4 = 0;
        break;
    case INVHIT_MODE_LOCKON_GATE:
        ((GameObject*)obj)->unkF8 = def[0x18];
        ((GameObject*)obj)->unkF4 = 0;
        break;
    case INVHIT_MODE_SELF_FREE:
        sub[0x62] = 1;
        ((ObjHitsPriorityState*)sub)->primaryRadius = def[0x18];
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
        ((ObjHitsPriorityState*)sub)->primaryRadius = def[0x18];
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
        ((ObjHitsPriorityState*)sub)->shapeFlags = def[0x19];
        ((ObjHitsPriorityState*)sub)->primaryRadius = def[0x18];
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
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | (INVHIT_OBJFLAG_HIDDEN | INVHIT_OBJFLAG_HITDETECT_DISABLED);
}
#pragma opt_common_subs reset

void invhit_update(int* obj)
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
            char* victim = Obj_GetPlayerObject();
            while (victim != NULL)
            {
                f32 dx = ((GameObject*)obj)->anim.localPosX - ((PushableState*)victim)->cullDistance;
                f32 dy = ((GameObject*)obj)->anim.localPosY - ((PushableState*)victim)->scale;
                f32 dz = ((GameObject*)obj)->anim.localPosZ - ((PushableState*)victim)->timer_0x14;
                f32 dist = sqrtf(dx * dx + dy * dy + dz * dz);
                if (dist < (f32)((GameObject*)obj)->unkF8)
                {
                    u8* victimHits = *(u8**)&((GameObject*)victim)->anim.hitReactState;
                    victimHits[0x71] += 1;
                    ((ObjHitsPriorityState*)victimHits)->flags = ((ObjHitsPriorityState*)victimHits)->flags & ~1;
                    (*(u8**)&((GameObject*)obj)->anim.hitReactState)[0x71] += 1;
                }
                if (((GameObject*)victim)->anim.classId == 1)
                {
                    victim = (char*)getTrickyObject();
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
                    Obj_FreeObject(obj);
                }
                ownerHitSlot += 4;
            }
            break;
        }
    case INVHIT_MODE_HOMING_PROJECTILE:
        {
            char* hitState = *(char**)&((GameObject*)obj)->anim.hitReactState;
            f32** hits[2];
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
                f32 k;
                f32 qt;
                f32 d;

                if (ObjList_ContainsObject((int)targetObj) == 0) break;
                dx = ((GameObject*)targetObj)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
                dz = ((GameObject*)targetObj)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
                k = lbl_803E35EC;
                qt = dx / k;
                ((GameObject*)obj)->anim.localPosX = qt * timeDelta + ((GameObject*)obj)->anim.localPosX;
                qt = dz / k;
                ((GameObject*)obj)->anim.localPosZ = qt * timeDelta + ((GameObject*)obj)->anim.localPosZ;
                dx = ((GameObject*)targetObj)->anim.localPosX - state->anchorX;
                dz = ((GameObject*)targetObj)->anim.localPosZ - state->anchorZ;
                reach = lbl_803E35F0 + sqrtf(dx * dx + dz * dz);
                dx2 = ((GameObject*)obj)->anim.localPosX - state->anchorX;
                dz2 = ((GameObject*)obj)->anim.localPosZ - state->anchorZ;
                d = sqrtf(dx2 * dx2 + dz2 * dz2);
                if (d > reach)
                {
                    f32 r = reach / d;
                    dx2 = dx2 * r;
                    dz2 = dz2 * r;
                    ((GameObject*)obj)->anim.localPosX = state->anchorX + dx2;
                    ((GameObject*)obj)->anim.localPosZ = state->anchorZ + dz2;
                }
                (*gPartfxInterface)->spawnObject(obj, 0x25, NULL, 0, -1,
                                                 NULL);
                (*gPartfxInterface)->spawnObject(obj, 0x56, NULL, 0, -1,
                                                 NULL);
            }
            {
                s8 tmp = (s8)hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                       ((GameObject*)obj)->anim.localPosZ, hits, 0, 0);
                i = 0;
                cnt = tmp;
            }
            thr = lbl_803E35F4;
            for (; i < cnt; i++)
            {
                f32 h = *hits[0][i];
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
