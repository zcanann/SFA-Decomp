#include "main/dll_000A_expgfx.h"
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/dll/TREX/TREX_levelcontrol.h"

extern u32 randomGetRange(int min, int max);

extern u8 framesThisStep;
extern EffectInterface** gPartfxInterface;

extern void objRenderFn_8003b8f4(f32);

extern f32 timeDelta;

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

extern ModgfxInterface** gModgfxInterface;

extern int lbl_803DC098;
extern f32 lbl_803E592C;
extern f32 lbl_803E5948;
extern f32 lbl_803E594C;
extern f32 lbl_803E5950;
extern void fn_80053ED0(int);
extern void fn_80053EBC(int);
extern f32 lbl_803E5928;
extern f64 lbl_803E5940;
extern f32 lbl_803E5930;
extern f32 lbl_803E5934;
extern f32 lbl_803E5938;
extern f32 lbl_803E593C;

void FUN_801e55c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined2* param_9, int param_10)
{
}

void SB_FireBall_release(void);

void SB_MiniFire_hitDetect(void)
{
}

void SB_MiniFire_release(void)
{
}

void SB_MiniFire_initialise(void)
{
}

void ShipBattle_hitDetect(void);

int SB_MiniFire_getExtraSize(void) { return 0x2; }
int SB_MiniFire_getObjectTypeId(void) { return 0x0; }
int ShipBattle_getExtraSize(void);

/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */

/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */

void SB_MiniFire_free(int* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->detachSource(obj);
}

void SB_MiniFire_init(int obj)
{
    extern void Sfx_PlayFromObject(int* obj, int sfxId);
    void* resource;

    ((GameObject*)obj)->unkF4 = 180;
    ((GameObject*)obj)->anim.velocityX = -(lbl_803E594C * (f32)(s32)
    randomGetRange(20, 40)
    )
    +lbl_803E5948;
    ((GameObject*)obj)->anim.velocityY = lbl_803E592C;
    ((GameObject*)obj)->anim.velocityZ = lbl_803E5950;
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * lbl_803E5948;

    resource = Resource_Acquire(117, 1);
    (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))(
        obj, lbl_803DC098, 0, 0x10002, -1, 0);
    lbl_803DC098++;
    if (lbl_803DC098 > 3)
    {
        lbl_803DC098 = 1;
    }
    Resource_Release(resource);
    Sfx_PlayFromObject((int*)obj, SFXen_ripefruit11);
    Sfx_PlayFromObject((int*)obj, SFXbaddie_crater_call);
}

void SB_MiniFire_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        fn_80053ED0(8);
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E5928);
        fn_80053EBC(8);
    }
}

void SB_MiniFire_update(int obj)
{
    extern void Obj_FreeObject(int obj);
    f32 buf[6];
    f32 dx;
    f32 dy;
    f32 dz;
    int dt;
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.
        localPosX;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
        localPosY;
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.
        localPosZ;
    buf[3] = lbl_803E592C;
    buf[4] = lbl_803E592C;
    buf[5] = lbl_803E592C;
    buf[2] = lbl_803E5928;
    if (((GameObject*)obj)->unkF4 <= 0x3c)
    {
        buf[2] = (f32)((GameObject*)obj)->unkF4 / lbl_803E5930;
        ((GameObject*)obj)->anim.alpha =
            (u8)(int)(lbl_803E5934 * ((f32)((GameObject*)obj)->unkF4 / *(f32*)&lbl_803E5930));
    }
    *(s16*)((char*)buf + 4) = 0;
    *(s16*)((char*)buf + 2) = 0;
    *(s16*)((char*)buf + 0) = 0;
    (*gPartfxInterface)->spawnObject((void*)obj, 0xa0, buf, 1, -1, NULL);
    dy = ((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)->anim.previousLocalPosY;
    dz = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ;
    dx = ((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX;
    buf[3] = dx / lbl_803E5938;
    buf[4] = dy / lbl_803E5938;
    buf[5] = dz / lbl_803E5938;
    (*gPartfxInterface)->spawnObject((void*)obj, 0xa0, buf, 1, -1, NULL);
    buf[3] = buf[3] * lbl_803E593C;
    buf[4] = buf[4] * lbl_803E593C;
    buf[5] = buf[5] * lbl_803E593C;
    (*gPartfxInterface)->spawnObject((void*)obj, 0xa0, buf, 1, -1, NULL);
    *(s16*)obj = *(s16*)obj + framesThisStep * 0x374;
    ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + framesThisStep * 0x12c;
    ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - framesThisStep;
    if (((GameObject*)obj)->unkF4 < 0)
    {
        Obj_FreeObject(obj);
    }
}

void SB_SeqDoor_init(int* obj, int* def);

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
