/*
 * dll_1CE: hatch-door object. The lid coasts open under a clamped velocity
 * while idle; once a key object (seqId 0x18F or 0x1D6) is in range it counts
 * down, sets its placement gamebit, and - if the load isn't locked and the
 * placement's unk1A bit matches gamebit 0x46D - spawns its contents object
 * (subtype 0x246) seeded from the door's transform.
 *
 * The TU also hosts dimmagicbridge_* and explosion_* sibling exports (in
 * DIM/dll_01CC_dimmagicbridge.c / DIM/dll_01CA_dimexplosion.c); their forward
 * declarations and the descriptor that combines them live in this object's DLL.
 */
#include "main/dll/dll1ceplacement_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/game_object.h"
#include "main/resource.h"

STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);

extern void objRenderFn_8003b8f4(int p1, int p2, int p3, int p4, int p5, f32 v);
extern f32 lbl_803E49E8;
extern void* lbl_803DDB78;
extern f32 lbl_803E49F0;
extern f32 timeDelta;
extern u8 Obj_IsLoadingLocked(void);
extern int* Obj_AllocObjectSetup(int a, int b);
extern void Obj_SetupObject(int* obj, int a, int b, int c, int d);
extern f32 lbl_803E49EC;
extern f32 lbl_803E49F4;
extern f32 lbl_803E49F8;
extern f32 lbl_803E49FC;

void dll_1CE_hitDetect(void)
{
}

void dll_1CE_release(void)
{
}

void dll_1CE_initialise(void)
{
}

int dll_1CE_getExtraSize(void) { return 0xc; }
int dll_1CE_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void dll_1CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E49E8);
}

#pragma scheduling on
#pragma peephole on
void dll_1CE_free(void)
{
    if (lbl_803DDB78 != NULL)
    {
        Resource_Release(lbl_803DDB78);
    }
    lbl_803DDB78 = NULL;
}

#pragma scheduling off
#pragma peephole off
void dll_1CE_init(u8* obj, u8* params)
{
    Dll1CEState* sub;
    ObjHitsPriorityState* hitState;
    *(s16*)obj = (s16)(((s16)(s8)params[0x18]) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
    sub = ((GameObject*)obj)->extra;
    sub->igniteCountdown = 1;
    if (GameBit_Get(*(s16*)(params + 0x1e)) != 0)
    {
        sub->igniteCountdown = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GameObject*)obj)->anim.alpha = 0;
    }
    sub->openVelocity = lbl_803E49F0;
}

#pragma opt_strength_reduction off
void dll_1CE_update(int* obj)
{
    int* q = *(int**)&((GameObject*)obj)->anim.placementData;
    Dll1CEState* sub = ((GameObject*)obj)->extra;
    ObjHitsPriorityState* hitState;
    if (((GameObject*)obj)->anim.alpha == 0) return;
    if ((s8)sub->igniteCountdown <= 0)
    {
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        if (sub->opened == 1)
        {
            sub->openProgress = sub->openVelocity * timeDelta + sub->openProgress;
            if (sub->openProgress > lbl_803E49EC)
            {
                sub->openProgress = lbl_803E49EC;
                sub->openVelocity = lbl_803E49F0;
            }
            else if (sub->openProgress < lbl_803E49F4)
            {
                sub->openProgress = lbl_803E49F4;
                sub->openVelocity = lbl_803E49F8;
            }
        }
    }
    if (((GameObject*)obj)->anim.seqId == 0x334) return;
    {
        int found = 0;
        int i = 0;
        int* list = *(int**)((char*)obj + 0x58);
        int n = (int)(*(s8*)((char*)*(int**)((char*)obj + 0x58) + 0x10f));
        for (; i < n; i++)
        {
            int* o = *(int**)((char*)list + i * 4 + 0x100);
            if (((GameObject*)o)->anim.seqId == 0x18f || ((GameObject*)o)->anim.seqId == 0x1d6)
            {
                found = 1;
                break;
            }
        }
        if (!found) return;
    }
    if ((s8)(sub->igniteCountdown -= 1) > 0) return;
    GameBit_Set(((Dll1CEPlacement*)q)->gameBitId, 1);
    sub->opened = 1;
    if ((u32)(s16)((Dll1CEPlacement*)q)->unk1A != GameBit_Get(0x46d)) return;
    if (Obj_IsLoadingLocked() == 0) return;
    {
        int* no = Obj_AllocObjectSetup(0x30, 0x246);
        *(f32*)((char*)no + 8) = ((Dll1CEPlacement*)q)->posX;
        *(f32*)((char*)no + 0xc) = lbl_803E49FC + ((Dll1CEPlacement*)q)->posYOffset;
        *(f32*)&((ObjDef*)no)->jointData = ((Dll1CEPlacement*)q)->posZ;
        *(u8*)((char*)no + 4) = ((Dll1CEPlacement*)q)->unk4;
        *(u8*)((char*)no + 5) = ((Dll1CEPlacement*)q)->unk5;
        *(u8*)((char*)no + 6) = ((Dll1CEPlacement*)q)->unk6;
        *(u8*)((char*)no + 7) = ((Dll1CEPlacement*)q)->unk7;
        *(s16*)((char*)no + 0x1c) = 0x17f;
        *(s16*)((char*)no + 0x24) = -1;
        *(s16*)((char*)no + 0x2c) = -1;
        *(u8*)((char*)no + 0x1a) = 5;
        *(u8*)((char*)no + 0x1b) = (u8)((s16) * (s16*)obj >> 8);
        Obj_SetupObject(no, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
    }
}

volatile FbWGPipe GXWGFifo : (0xCC008000);
