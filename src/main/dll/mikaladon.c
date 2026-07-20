/*
 * mikaladon - the firefly-hover update handler (mikaladon_update) plus spawn-time
 * setup for the mikaladon enemy, dispatched by object seqId from the tricky
 * (DLL 0x00C4) and enemy (DLL 0x00C9) object DLLs. mikaladon_update drives a
 * circular drift, bobs between two heights, periodically drops a spawned
 * object and runs ambient sfx timers; mikaladon_init seeds the per-instance
 * speed/anim scales and the curve-path step, then places the actor at its
 * initial position along the path.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/audio/sfx.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_placement.h"
#include "main/vecmath.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/voxmaps.h"
#include "main/dll/mikaladon.h"

#define MAGICPLANT_OBJFLAG_PARENT_SLACK 0x1000

/* Spit projectile spawned by kooshy_spawnProjectile; retail OBJECTS.bin name
   "KaldachomSp" (DLL 0xD7 kaldachompspit), shared with the snowworm spitter. */
#define KALDACHOM_SPIT_OBJ 0x51b

/* The magic-plant's one particle-fx effect (spawned per hit-count in the
   attack handler). */
#define MAGICPLANT_PARTFX          0x802
#define MAGICPLANT_HIT_VOLUME_SLOT 0xe

/* gcRobotPatrol (mikaladon_update): periodically dropped object; parented back to
 * the dropper via +0xC4 and announced with SFX 0x249. */
#define SEQOBJ11E_GCROBOT_DROP_OBJ 0x6b5

extern const f32 lbl_803E2868;
extern const f32 lbl_803E286C;

static f32 seq11e_intToFloat(int n)
{
    return (f32)n;
}

/* mikaladon_update: firefly hover update: circle drift, bob between heights,
 * periodically drop a spawned object, ambient sfx timers. */
void mikaladon_update(int* obj, u8* state)
{
    f32 y;
    f32 sinOut;
    f32 cosOut;

    *(u16*)(state + 0x338) = 75.0f * timeDelta + (f32)(u32) * (u16*)(state + 0x338);
    fn_80293018(*(u16*)(state + 0x338), &sinOut, &cosOut);
    sinOut = sinOut * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x324);
    cosOut = cosOut * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x32c);
    if (((BaddieState*)state)->userData1 == 0)
    {
        f32 dx;
        f32 dz;

        y = ((GameObject*)obj)->anim.localPosY;
        dx = *(f32*)(state + 0x324) - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX;
        dz = *(f32*)(state + 0x32c) - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ;
        if (sqrtf(dx * dx + dz * dz) <= 1.3f * ((BaddieState*)state)->unk2A8)
        {
            ((BaddieState*)state)->userData1 = 1;
            ((BaddieState*)state)->userData2 = 0;
        }
    }
    else if (((BaddieState*)state)->userData1 == 1)
    {
        y = ((GameObject*)obj)->anim.localPosY - 0.5f * timeDelta;
        if (y <= *(f32*)(state + 0x328) - 500.0f)
        {
            ((BaddieState*)state)->userData1 = 2;
        }
        else
        {
            ((BaddieState*)state)->userData2 = (f32)(u32)((BaddieState*)state)->userData2 + timeDelta;
            if (((BaddieState*)state)->userData2 > 0x64)
            {
                ((BaddieState*)state)->userData2 = 0;
                if (Obj_IsLoadingLocked() != 0)
                {
                    u8* setup;
                    int* spawned;

                    setup = (u8*)Obj_AllocObjectSetup(0x24, SEQOBJ11E_GCROBOT_DROP_OBJ);
                    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                    ((ObjPlacement*)setup)->posY = 5.0f + ((GameObject*)obj)->anim.localPosY;
                    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                    ((ObjPlacement*)setup)->color[0] = 1;
                    ((ObjPlacement*)setup)->color[1] = 1;
                    ((ObjPlacement*)setup)->color[2] = 0xff;
                    ((ObjPlacement*)setup)->color[3] = 0xff;
                    spawned = (int*)loadObjectAtObject((GameObject*)obj, (ObjPlacement*)setup);
                    if (spawned != 0)
                    {
                        ((GameObject*)spawned)->ownerObj = obj;
                        Sfx_PlayFromObject((u32)obj, SFXTRIG_id_249);
                    }
                }
            }
        }
    }
    else
    {
        y = 1.5f * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (y >= *(f32*)(state + 0x328))
        {
            ((BaddieState*)state)->userData1 = 0;
        }
    }
    ((GameObject*)obj)->anim.velocityX = oneOverTimeDelta * (sinOut - ((GameObject*)obj)->anim.localPosX);
    ((GameObject*)obj)->anim.velocityY = oneOverTimeDelta * (y - ((GameObject*)obj)->anim.localPosY);
    ((GameObject*)obj)->anim.velocityZ = oneOverTimeDelta * (cosOut - ((GameObject*)obj)->anim.localPosZ);
    fn_8014CD1C((GameObject*)obj, state, 0xf, 7.5f, 1.0f, 0);
    *(f32*)(state + 0x334) = *(f32*)(state + 0x334) - timeDelta;
    if (*(f32*)(state + 0x334) <= lbl_803E2868)
    {
        *(f32*)(state + 0x334) = (f32)(int)randomGetRange(0x3c, 0x78);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_id_31);
    }
    *(f32*)(state + 0x330) = *(f32*)(state + 0x330) - timeDelta;
    if (*(f32*)(state + 0x330) <= lbl_803E2868)
    {
        *(f32*)(state + 0x330) = lbl_803E286C;
        Sfx_PlayFromObject((u32)obj, SFXTRIG_id_24a);
    }
}

void mikaladon_init(GameObject* obj, int state)
{
    f32 zero;
    f32 lblA;
    f32 a, b;

    zero = lbl_803E286C;
    ((BaddieState*)state)->speedScale = zero;
    ((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk308 = 0.01f;
    ((BaddieState*)state)->animDeltaScale = 0.006f;
    lblA = 1.0f;
    ((BaddieState*)state)->unk304 = lblA;
    ((BaddieState*)state)->unk320 = 1;
    *(f32*)&((BaddieState*)state)->eventFlags = lblA;
    ((BaddieState*)state)->unk321 = 3;
    ((BaddieState*)state)->unk318 = lblA;
    ((BaddieState*)state)->unk322 = 1;
    ((BaddieState*)state)->unk31C = lblA;
    *(f32*)(state + 0x324) = obj->anim.localPosX;
    *(f32*)(state + 0x328) = obj->anim.localPosY;
    *(f32*)(state + 0x32c) = obj->anim.localPosZ;
    ((BaddieState*)state)->userData1 = 0;
    ((BaddieState*)state)->userData2 = 0;
    *(s16*)(state + 0x338) = 0;
    *(f32*)(state + 0x330) = zero;
    *(f32*)(state + 0x334) = zero;
    ((BaddieState*)state)->pathStep = 8.0f;

    fn_80293018(*(u16*)(state + 0x338), &a, &b);
    obj->anim.localPosX = a * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x324);
    obj->anim.localPosZ = b * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x32c);
}
