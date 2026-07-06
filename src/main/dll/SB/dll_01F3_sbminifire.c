/*
 * sbminifire (DLL 0x1F3) - the small fire/spark projectile spawned during
 * the ShipBattle (SB) set. At init it picks a randomised launch velocity,
 * a cycling resource variant (gSbMiniFireResourceVariant, 1..3) and plays its spawn
 * sfx. Each tick it integrates its position, spins, spawns three partfx
 * bursts (a base puff, a velocity-aligned trail and a scaled trail),
 * fades out over its final frames and frees itself when its lifetime
 * (unkF4) expires.
 */
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/resource.h"
#include "main/engine_shared.h"

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
extern int gSbMiniFireResourceVariant;
extern void fn_80053ED0(int);
extern void fn_80053EBC(int);


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

void SB_MiniFire_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->detachSource(obj);
}

void SB_MiniFire_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        fn_80053ED0(8);
        ((void(*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(p1, p2, p3, p4, p5, 1.0f);
        fn_80053EBC(8);
    }
}

void SB_MiniFire_hitDetect(void)
{
}

void SB_MiniFire_update(GameObject* obj)
{
    extern void Obj_FreeObject(int obj);
    f32 buf[6];
    f32 dx;
    f32 dy;
    f32 dz;
    obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
    obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
    obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
    buf[3] = 0.0f;
    buf[4] = 0.0f;
    buf[5] = 0.0f;
    buf[2] = 1.0f;
    if (obj->unkF4 <= 0x3c)
    {
        buf[2] = obj->unkF4 / 60.0f;
        obj->anim.alpha =
            (u8)(int)(255.0f * ((f32)obj->unkF4 / 60.0f));
    }
    *(s16*)((char*)buf + 4) = 0;
    *(s16*)((char*)buf + 2) = 0;
    *(s16*)((char*)buf + 0) = 0;
    (*gPartfxInterface)->spawnObject((void*)obj, 0xa0, buf, 1, -1, NULL);
    dy = obj->anim.localPosY - obj->anim.previousLocalPosY;
    dz = obj->anim.localPosZ - obj->anim.previousLocalPosZ;
    dx = obj->anim.localPosX - obj->anim.previousLocalPosX;
    buf[3] = dx / 3.0f;
    buf[4] = dy / 3.0f;
    buf[5] = dz / 3.0f;
    (*gPartfxInterface)->spawnObject((void*)obj, 0xa0, buf, 1, -1, NULL);
    buf[3] *= 2.0f;
    buf[4] *= 2.0f;
    buf[5] *= 2.0f;
    (*gPartfxInterface)->spawnObject((void*)obj, 0xa0, buf, 1, -1, NULL);
    obj->anim.rotX = obj->anim.rotX + framesThisStep * 0x374;
    obj->anim.rotY = obj->anim.rotY + framesThisStep * 0x12c;
    obj->unkF4 = obj->unkF4 - framesThisStep;
    if (obj->unkF4 < 0)
    {
        Obj_FreeObject((int)obj);
    }
}

void SB_MiniFire_init(GameObject* obj)
{
    extern void Sfx_PlayFromObject(int* obj, int sfxId);
    void* resource;

    obj->unkF4 = 180;
    obj->anim.velocityX =
        -(0.01f * (f32)(s32)randomGetRange(20, 40) + 0.8f);
    obj->anim.velocityY = 0.0f;
    obj->anim.velocityZ = -0.3f;
    obj->anim.rootMotionScale *= 0.8f;

    resource = Resource_Acquire(117, 1);
    (*(void (**)(int, int, int, int, int, int))(*(int*)resource + 4))(
        (int)obj, gSbMiniFireResourceVariant, 0, 0x10002, -1, 0);
    gSbMiniFireResourceVariant++;
    if (gSbMiniFireResourceVariant > 3)
    {
        gSbMiniFireResourceVariant = 1;
    }
    Resource_Release(resource);
    Sfx_PlayFromObject((int*)obj, SFXen_ripefruit11);
    Sfx_PlayFromObject((int*)obj, SFXbaddie_crater_call);
}

void SB_MiniFire_release(void)
{
}

void SB_MiniFire_initialise(void)
{
}


/* EN v1.0 0x801E60A4  size: 28b  shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash v in obj->_b8[4]. */

/* EN v1.0 0x801E607C  size: 40b  Increment-and-store: obj->_b8[2] += p3,
 * obj->_b8[3] += p2. */

/* EN v1.0 0x801E6050  size: 44b  Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */

/* EN v1.0 0x801E6358  size: 104b  Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */

/* EN v1.0 0x801E62F0  size: 104b  Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */
