/* DLL 0x01F5 — ShipBattle (Lylat Cruise ship-battle sequence, chain/fireball/cage/cloudball). TU: 0x801E55B8–0x801E59AC. */
#include "main/dll_000A_expgfx.h"
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/dll/TREX/TREX_levelcontrol.h"

extern void objRenderFn_8003b8f4(f32);

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/dll/TREX/TREX_trex.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/objhits_types.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct ShipBattleObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x24 - 0x1C];
    u8 unk24;
    u8 pad25[0x28 - 0x25];
} ShipBattleObjectDef;

/*
 * Per-object extra state for the ShipBattle cloud-ball projectile
 * (SB_CloudBall_getExtraSize == 0x24).
 */

STATIC_ASSERT(sizeof(SBCloudBallState) == 0x24);

/*
 * Per-object extra state for the ShipBattle fireball projectile
 * (SB_FireBall_getExtraSize == SB_FIREBALL_EXTRA_SIZE == 0x18).
 */

STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);

/*
 * Per-object extra state for the ShipBattle kyte cage
 * (SB_KyteCage_getExtraSize == 0x8).
 */

STATIC_ASSERT(sizeof(SBKyteCageState) == 0x8);

/*
 * Per-object extra state for the ShipBattle chain segment
 * (ShipBattle_getExtraSize == 0x140). The head is handed to
 * gObjectTriggerInterface (+0x1C/+0x24) - interface-owned record;
 * only the locally-evidenced fields are named.
 */

STATIC_ASSERT(sizeof(ShipBattleState) == 0x140);
extern int* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy

extern f32 lbl_803E5958;
extern f32 lbl_803E595C;
extern f32 lbl_803E5970;
extern f32 lbl_803E5974;
extern f32 lbl_803E5960;
extern u8 lbl_803DB411;
extern f32 lbl_803DDC50;

void FUN_801e55c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined2* param_9, int param_10)
{
}

void SB_FireBall_release(void);

void ShipBattle_hitDetect(void)
{
}

void ShipBattle_release(void)
{
}

void ShipBattle_initialise(void)
{
}

void Flag_free(void);

int ShipBattle_getExtraSize(void) { return 0x140; }
int ShipBattle_getObjectTypeId(void) { return 0xb; }
int Lamp_getExtraSize(void);

/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */

/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */

void ShipBattle_free(int* obj)
{
    extern void ModelLightStruct_free(int* p);
    int* state = ((GameObject*)obj)->extra;
    (*gObjectTriggerInterface)->freeState((u8*)state);
    ((void(*)(int*, int, int, int, int))((void**)*gTitleMenuControlInterface)[2])(obj, 0xffff, 0, 0, 0);
    {
        int light = ((GameObject*)obj)->unkF8;
        if (light != 0)
        {
            ModelLightStruct_free((int*)light);
        }
    }
}

void ShipBattle_init(int obj, int def)
{
    extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
    extern void modelLightStruct_setDiffuseColor(int light, int p, int r, int g, int p2);
    extern void modelLightStruct_setLightKind(int light, int v);
    extern int objCreateLight(int* obj, int mode);
    ShipBattleState* state;
    int light;
    int chainIndex;

    state = ((GameObject*)obj)->extra;
    state->unk6A = ((ShipBattleObjectDef*)def)->unk1A;
    state->unk6E = -1;
    state->unk24 =
        lbl_803E595C / (lbl_803E595C + (f32)((ShipBattleObjectDef*)def)->unk24);
    state->unk28 = -1;

    chainIndex = ((GameObject*)obj)->unkF4;
    if (chainIndex == 0)
    {
        if (((ShipBattleObjectDef*)def)->unk18 != 1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)def);
            ((GameObject*)obj)->unkF4 = ((ShipBattleObjectDef*)def)->unk18 + 1;
            goto light_setup;
        }
    }

    if (chainIndex != 0)
    {
        if (((ShipBattleObjectDef*)def)->unk18 != chainIndex - 1)
        {
            (*gObjectTriggerInterface)->freeState((u8*)state);
            if (((ShipBattleObjectDef*)def)->unk18 != -1)
            {
                (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)def);
            }
            ((GameObject*)obj)->unkF4 = ((ShipBattleObjectDef*)def)->unk18 + 1;
        }
    }

light_setup:
    if (((GameObject*)obj)->anim.seqId == 0x171)
    {
        light = objCreateLight((int*)obj, 1);
        if ((u32)light != 0)
        {
            modelLightStruct_setLightKind(light, 2);
            modelLightStruct_setDiffuseColor(light, 200, 60, 0, 0);
            modelLightStruct_setDistanceAttenuation(light, lbl_803E5970, lbl_803E5974);
        }
        ((GameObject*)obj)->unkF8 = light;
    }

    lbl_803DDC50 = lbl_803E5958;
    *(u8*)((char*)&lbl_803DDC50 + 4) = 0;
}

void ShipBattle_render(int* obj)
{
    extern void objfx_spawnFlaggedTrailBurst(int* obj, f32 f, int a, int b, int c, void* d);
    objRenderFn_8003b8f4(lbl_803E595C);
    if (((GameObject*)obj)->anim.seqId == 369)
    {
        objfx_spawnFlaggedTrailBurst(obj, lbl_803E5960, 4, 389, 5, NULL);
    }
}

void ShipBattle_update(int obj)
{
    extern int* ObjList_GetObjects(int* out_head, int* out_count);
    extern void Obj_FreeObject(int obj);
    int* objects;
    int triggerResult;
    int objectCount;
    int current;
    int linkedObject;
    int sameGroupCount;
    int groupId;

    if (((GameObject*)obj)->anim.placementData == NULL)
    {
        return;
    }
    if (*(s16*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x18) == -1)
    {
        return;
    }

    triggerResult = (*gObjectTriggerInterface)->update((u8*)obj, (f32)lbl_803DB411);
    if (triggerResult == 0 || ((GameObject*)obj)->seqIndex != -2)
    {
        return;
    }

    groupId = *(s8*)(*(int*)&((GameObject*)obj)->extra + 0x57);
    linkedObject = 0;
    objects = ObjList_GetObjects(&triggerResult, &objectCount);
    sameGroupCount = 0;
    triggerResult = 0;
    while (triggerResult < objectCount)
    {
        current = objects[triggerResult];
        if (*(s16*)(current + 0xb4) == groupId)
        {
            linkedObject = current;
        }
        if (*(s16*)(current + 0xb4) == -2 && *(s16*)(current + 0x44) == 0x10 &&
            groupId == *(s8*)(*(int*)(current + 0xb8) + 0x57))
        {
            sameGroupCount++;
        }
        triggerResult++;
    }

    if (sameGroupCount <= 1 && (void*)linkedObject != NULL && *(s16*)(linkedObject + 0xb4) != -1)
    {
        *(s16*)(linkedObject + 0xb4) = -1;
        (*gObjectTriggerInterface)->endSequence(groupId);
    }
    ((GameObject*)obj)->seqIndex = -1;
    Obj_FreeObject(obj);
}

void shop_buyItem(int obj, int price);

/* EN v1.0 0x801E60A4  size: 28b  shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash (s8)v in obj->_b8[4]. */

/* EN v1.0 0x801E607C  size: 40b  Increment-and-store: obj->_b8[2] += p3,
 * obj->_b8[3] += p2. */

/* EN v1.0 0x801E6050  size: 44b  Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */

/* EN v1.0 0x801E6358  size: 104b  Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */

/* EN v1.0 0x801E62F0  size: 104b  Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */
