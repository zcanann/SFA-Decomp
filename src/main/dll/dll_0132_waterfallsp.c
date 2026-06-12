/* === moved from main/dll/MMP/MMP_asteroid.c [801978A0-801978A8) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/effect_interfaces.h"











extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);

extern EffectInterface** gPartfxInterface;

/*
 * --INFO--
 *
 * Function: xyzanimator_update
 * EN v1.0 Address: 0x80195008
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x801950E0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801950ac
 * EN v1.0 Address: 0x801950AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019518C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801954f0
 * EN v1.0 Address: 0x801954F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80195584
 * EN v1.1 Size: 4624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801954f4
 * EN v1.0 Address: 0x801954F4
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x80196794
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80195b40
 * EN v1.0 Address: 0x80195B40
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80196EA8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80195b74
 * EN v1.0 Address: 0x80195B74
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80196ED8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off















extern u8 framesThisStep;



/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */



/* ObjGroup_RemoveObject(x, N) wrappers. */

/* state encode: ((obj->_X)->_Y << shift) | const. */

/* Drift-recovery: add new fns with v1.0 names. */











extern f32 sqrtf(f32);

/* EN v1.0 0x80196990  size: 1752b  dimbossicesmash_update: gate on the
 * trigger gamebit, integrate velocity/rotation with per-axis gravity
 * clamps, run the path-control hooks with surface bounce, fade alpha over
 * the lifetime window, and emit the two trail particles. */


/* EN v1.0 0x80196520  size: 1008b  fn_80196520: seed the icesmash launch
 * state from the setup record: spawn position/rotation, launch velocity
 * (optionally homing on the target point), rotation velocities and the
 * gravity/clamp direction flags. */

/* EN v1.0 0x80197068  size: 284b  dimbossicesmash_init. */


/* EN v1.0 0x80197474  size: 648b  fogcontrol_update: ramp the fog blend
 * toward the gamebit-selected target and feed the heavy fog params. */

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/dll/MMP/MMP_moonrock.h"
#include "main/camera_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"







typedef struct WaterFallSprayState
{
    u32 unk0;
    u32 unk4;
} WaterFallSprayState;




extern u8* Obj_GetPlayerObject(void);
extern f32 sqrtf(f32 value);


/*
 * --INFO--
 *
 * Function: lightning_free
 * EN v1.0 Address: 0x801978A8
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801978DC
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* lightning_free: ObjGroup_RemoveObject + free of obj->_b8->_0 if non-null. */


/* lightning_render: deref obj->_b8->_0 (effect handle); if non-null call
 * lightningRender(handle). */







void WaterFallSpray_free(u8* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

typedef struct WaterFallSprayPartfxArgs
{
    u32 pad0;
    u32 pad1;
    u32 pad2;
    f32 xOffset;
    f32 yOffset;
    f32 zOffset;
} WaterFallSprayPartfxArgs;

#define WATERFALLSPRAY_SPAWN_PARTICLE(obj, id, args) \
    (*gPartfxInterface)->spawnObject( \
        (obj), (id), (args), 4, -1, 0)

void WaterFallSpray_update(int* objParam)
{
    extern void Sfx_KeepAliveLoopedObjectSound(u8* obj, int sfxId); /* #57 */
    u8* obj;
    u32* state;
    u8* data;
    u8* player;
    WaterFallSprayPartfxArgs partfxArgs;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    int cooldown;
    s16 i;

    obj = (u8*)objParam;
    state = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    if (player != NULL)
    {
        if (*(s16*)(data + 0x18) != -1)
        {
            i = GameBit_Get(*(s16*)(data + 0x18));
        }
        else
        {
            i = 1;
        }
        if (i != 0)
        {
            if ((data[0x23] & 0x10) == 0)
            {
                Sfx_KeepAliveLoopedObjectSound(obj, state[0] & 0xffff);
                Sfx_KeepAliveLoopedObjectSound(obj, state[1] & 0xffff);
            }

            cooldown = ((GameObject*)obj)->unkF4;
            if (cooldown <= 0)
            {
                dx = ((GameObject*)obj)->anim.worldPosX - *(f32*)(player + 0x18);
                dy = ((GameObject*)obj)->anim.worldPosY - *(f32*)(player + 0x1c);
                dz = ((GameObject*)obj)->anim.worldPosZ - *(f32*)(player + 0x20);
                distance = sqrtf(dz * dz + (dx * dx + dy * dy));
                if (((distance <= (f32)(s32)((u32)data[0x20] << 4)) || (data[0x20] == 0)) &&
                    ((((GameObject*)obj)->objectFlags & 0x800) != 0))
                {
                    for (i = 0; i < data[0x24]; i++)
                    {
                        partfxArgs.xOffset = (f32)(s32)
                        randomGetRange(-data[0x1d], data[0x1d]);
                        partfxArgs.yOffset = (f32)(s32)
                        randomGetRange(-data[0x1f], data[0x1f]);
                        partfxArgs.zOffset = (f32)(s32)
                        randomGetRange(-data[0x1e], data[0x1e]);
                        if ((data[0x23] & 1) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x320, &partfxArgs);
                        }
                        if ((data[0x23] & 2) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x321, &partfxArgs);
                        }
                        if ((data[0x23] & 4) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x322, &partfxArgs);
                        }
                        if ((data[0x23] & 8) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x351, &partfxArgs);
                        }
                    }
                }
                *(u32*)&((GameObject*)obj)->unkF4 = -(u32)data[0x24];
            }
            else if (cooldown > 0)
            {
                *(u32*)&((GameObject*)obj)->unkF4 = cooldown - (u32)framesThisStep;
            }
        }
    }
}

/* WaterFallSpray_init: stash 3 signed-byte<<8 fields at obj+0..+4, clear
 * obj+0xf4, install WaterFallSpray_SeqFn as the think routine at obj+0xbc, then
 * pick one of two SFX-id pairs based on the range of obj->_4c->_14. */
void WaterFallSpray_init(u8* obj, u8* data)
{
    u8* sub = ((GameObject*)obj)->extra;
    s16 a, b, c;
    int v;
    a = (s16)((s32)(s8)data[0x1a] << 8);
    ((GameObject*)obj)->anim.rotZ = a;
    b = (s16)((s32)(s8)data[0x1b] << 8);
    ((GameObject*)obj)->anim.rotY = b;
    c = (s16)((s32)(s8)data[0x1c] << 8);
    ((GameObject*)obj)->anim.rotX = c;
    *(u32*)&((GameObject*)obj)->unkF4 = 0;
    ((GameObject*)obj)->animEventCallback = (void*)WaterFallSpray_SeqFn;
    v = *(int*)((char*)(*(u8**)&((GameObject*)obj)->anim.placementData) + 0x14);
    if (v < WATERFALLSPRAY_ALT_SFX_DEF_END)
    {
        if (v >= WATERFALLSPRAY_ALT_SFX_DEF_MIN)
        {
            ((WaterFallSprayState*)sub)->unk0 = WATERFALLSPRAY_ALT_SFX_A;
            ((WaterFallSprayState*)sub)->unk4 = WATERFALLSPRAY_ALT_SFX_B;
            return;
        }
    }
    ((WaterFallSprayState*)sub)->unk0 = WATERFALLSPRAY_DEFAULT_SFX_A;
    ((WaterFallSprayState*)sub)->unk4 = WATERFALLSPRAY_DEFAULT_SFX_B;
}

/* sfxplayerObj_init: prime obj->_b0 with SFXPLAYER_OBJECT_FLAGS, then dispatch
 * on (s8)data->_1d: gamebit mode stores GameBit_Get(data->_18) at sub[0] if the
 * event id is positive; random-delay mode computes randomGetRange(data->_1e, data->_1f)
 * scaled by lbl_803E40BC as f32; cases 1 and >=3 are no-ops. */
extern f32 lbl_803E40BC;

void sfxplayerObj_init(u8* obj, u8* data);

/* sfxplayerObj_free: bit-0 of obj->_b8->_4 gates teardown. When set, clear
 * it and stop two sfx loops (data->_1a and data->_22). Mode depends on
 * data->_1d: 1 → Sfx_RemoveLoopedObjectSound, else Sfx_StopFromObject. */








/*
 * --INFO--
 *
 * Function: FUN_80197960
 * EN v1.0 Address: 0x80197960
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801979B8
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80197e54
 * EN v1.0 Address: 0x80197E54
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80197E64
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80197e84
 * EN v1.0 Address: 0x80197E84
 * EN v1.0 Size: 940b
 * EN v1.1 Address: 0x80197E94
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8019836c
 * EN v1.0 Address: 0x8019836C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80198350
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801983a0
 * EN v1.0 Address: 0x801983A0
 * EN v1.0 Size: 660b
 * EN v1.1 Address: 0x80198384
 * EN v1.1 Size: 916b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void WaterFallSpray_render(void)
{
}

/* 8b "li r3, N; blr" returners. */
int WaterFallSpray_getExtraSize(void) { return 0x8; }
int sfxplayerObj_getExtraSize(void);

int WaterFallSpray_SeqFn(int* obj)
{
    WaterFallSpray_update(obj);
    return 0;
}
