/* DLL 0x01F4 — lamp / ship-battle objects [801E4288-801E42F8) */
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/dll/TREX/TREX_levelcontrol.h"

extern u32 randomGetRange(int min, int max);
extern undefined4 ObjPath_GetPointWorldPosition();

extern void Sfx_StopObjectChannel();
extern u8 framesThisStep;

extern void objRenderFn_8003b8f4(f32);

extern f32 timeDelta;

#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/TREX/TREX_trex.h"
#include "main/dll_000A_expgfx.h"

typedef struct LampObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    u8 unk1A;
    u8 pad1B[0x20 - 0x1B];
} LampObjectDef;

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

extern f32 lbl_803E5978;
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern f32 lbl_803E597C;
extern f32 lbl_803E5980;
extern f32 lbl_803E5984;
extern f32 lbl_803E5988;
extern f32 lbl_803E598C;

void FUN_801e55c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined2* param_9, int param_10)
{
}

void SB_FireBall_release(void);

int Lamp_getExtraSize(void) { return 0x1; }
int Flag_getExtraSize(void);

int Lamp_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

void Lamp_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5978);
}

void Flag_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */

int Lamp_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern void* Obj_GetPlayerObject(void);
    u8 effectArgs[0x18];
    int i;

    if ((s32)randomGetRange(0, 1) != 0)
    {
        animUpdate->sequenceControlFlags = OBJSEQ_CONTROL_SET_LATCH_A;
    }
    else
    {
        animUpdate->sequenceControlFlags = OBJSEQ_CONTROL_CLEAR_LATCH_A;
    }
    animUpdate->sequenceEventActive = 0;
    animUpdate->hitVolumePair = -1;
    animUpdate->hitVolumePair &= ~0x20;

    if (Obj_GetPlayerObject() == NULL)
    {
        return 0;
    }
    if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
    {
        *(f32*)(effectArgs + 8) = lbl_803E597C;
        *(s16*)(effectArgs + 6) = 0xc0d;
        *(f32*)(effectArgs + 0xc) = *(f32*)(effectArgs + 0xc) - ((GameObject*)obj)->anim.worldPosX;
        *(f32*)(effectArgs + 0x10) = *(f32*)(effectArgs + 0x10) - ((GameObject*)obj)->anim.worldPosY;
        *(f32*)(effectArgs + 0x14) = *(f32*)(effectArgs + 0x14) - ((GameObject*)obj)->anim.worldPosZ;
        for (i = 0; i < framesThisStep; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7a8, effectArgs, 6, -1, NULL);
        }
    }
    return 0;
}

int fn_801E66EC(int arg1, int arg2);

void Lamp_free(int* obj)
{
    Sfx_StopObjectChannel(obj, 64);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void Lamp_init(int* obj, int* def)
{
    int* state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == 996)
    {
        *(s16*)obj = (s16)((u32)((LampObjectDef*)def)->unk1A << 8);
    }
    else
    {
        *(s16*)obj = (s16)((s32)((LampObjectDef*)def)->unk18 << 8);
    }
    ((GameObject*)obj)->anim.rotY = 0;
    ((GameObject*)obj)->anim.rotZ = 0;
    ((GameObject*)obj)->unkF8 = 0;
    *(s8*)state = 1;
    ((GameObject*)obj)->animEventCallback = (void*)Lamp_SeqFn;
}

void Lamp_update(int obj)
{
    extern f32 Vec_distance(void* a, void* b);
    extern void* Obj_GetPlayerObject(void);
    extern void Sfx_PlayFromObject(int* obj, int sfxId);
    u8 effectArgs[0x18];
    f32 distance;
    int i;

    distance = Vec_distance((void*)((int)Obj_GetPlayerObject() + 0x18), (void*)(obj + 0x18));
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) == 0)
    {
        if (distance < lbl_803E5980)
        {
            Sfx_PlayFromObject((int*)obj, SFXmn_eggylaugh216);
        }
    }
    else if (distance >= lbl_803E5980)
    {
        Sfx_StopObjectChannel((int*)obj, 0x40);
    }

    if (((GameObject*)obj)->anim.seqId != 0x3e4)
    {
        if (((GameObject*)obj)->unkF8 == 0)
        {
            ((GameObject*)obj)->unkF8 = 1;
            ObjAnim_SetMoveProgress((f32)(s32)randomGetRange(0, 90) / lbl_803E5980,
                                    (ObjAnimComponent*)obj);
        }
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E5984,
                                                                     timeDelta, NULL);
    }

    if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
    {
        *(f32*)(effectArgs + 8) = lbl_803E597C;
        *(s16*)(effectArgs + 6) = 0xc0d;
        *(f32*)(effectArgs + 0xc) = lbl_803E5988;
        *(f32*)(effectArgs + 0x10) = lbl_803E598C;
        *(f32*)(effectArgs + 0x14) = lbl_803E5988;
        ObjPath_GetPointWorldPosition(obj, 0, (f32*)(effectArgs + 0xc), (f32*)(effectArgs + 0x10),
                                      (f32*)(effectArgs + 0x14), 1);
        if (((GameObject*)obj)->anim.parent != NULL)
        {
            *(f32*)(effectArgs + 0xc) = *(f32*)(effectArgs + 0xc) - ((GameObject*)obj)->anim.worldPosX;
            *(f32*)(effectArgs + 0x10) = *(f32*)(effectArgs + 0x10) - ((GameObject*)obj)->anim.worldPosY;
            *(f32*)(effectArgs + 0x14) = *(f32*)(effectArgs + 0x14) - ((GameObject*)obj)->anim.worldPosZ;
        }
        else
        {
            *(f32*)(effectArgs + 0xc) = *(f32*)(effectArgs + 0xc) - ((GameObject*)obj)->anim.localPosX;
            *(f32*)(effectArgs + 0x10) = *(f32*)(effectArgs + 0x10) - ((GameObject*)obj)->anim.localPosY;
            *(f32*)(effectArgs + 0x14) = *(f32*)(effectArgs + 0x14) - ((GameObject*)obj)->anim.localPosZ;
        }
        for (i = 0; i < framesThisStep; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7c7, effectArgs, 2, -1, NULL);
        }
    }
}

void SB_CageKyte_init(int p);

/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */

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
