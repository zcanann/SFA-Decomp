#include "main/dll/mmp_asteroid_re.h"
#include "main/game_object.h"

typedef struct CfDoorlightObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 frameStep;
    u8 pad1E[0x20 - 0x1E];
} CfDoorlightObjectDef;


extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);
extern void* objFindTexture(void* obj, int target, int param_3);


typedef struct CfDoorLightState
{
    s32 textureId;
    u8 frameStep;
    u8 pad05[0x8 - 0x5];
    s32 maxFrame;
    s32 resetFrame;
    s32 currentFrame;
    u8 flags;
    u8 pad15[0x18 - 0x15];
} CfDoorLightState;

typedef struct CfDoorLightDef
{
    u8 pad00[0x1e];
    s16 doneEvent;
    s16 triggerEvent;
} CfDoorLightDef;

typedef struct BarrelPadParticleArgs
{
    u8 pad00[0xc];
    f32 offset[3];
} BarrelPadParticleArgs;

/*
 * --INFO--
 *
 * Function: transporter_init
 * EN v1.0 Address: 0x801916A0
 * EN v1.0 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Recovered: large switch on params[20] (32-bit id) that sets bits in
 * state->flags per map/area id. Six GameBit-guarded cases set bit 0x20 only
 * when any of 3 listed event bits is set; the rest set 0x68, 0x08, 0x30, or
 * 0x10 directly. Tail: if state->flags & 0x40 (which 0x68 includes), set
 * obj->_af |= 8 (redundant with the unconditional prologue store).
 */

/*
 * --INFO--
 *
 * Function: FUN_801916e8
 * EN v1.0 Address: 0x801916E8
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80191BD4
 * EN v1.1 Size: 72b
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
 * Function: FUN_80191730
 * EN v1.0 Address: 0x80191730
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80191C1C
 * EN v1.1 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/* Trivial 4b 0-arg blr leaves. */
void cflightwall_free(void)
{
}

void cflightwall_hitDetect(void)
{
}

void cflightwall_update(void)
{
}

void cflightwall_release(void)
{
}

void cflightwall_initialise(void)
{
}

void barrelpad_free(void);

void barrelpad_hitDetect(void);

void barrelpad_release(void);

void barrelpad_initialise(void);

void cf_doorlight_free(void);

void cf_doorlight_render(void);

void cf_doorlight_hitDetect(void);

void cf_doorlight_release(void);

void cf_doorlight_initialise(void);

/* 8b "li r3, N; blr" returners. */
int cflightwall_getExtraSize(void) { return 0x0; }
int cflightwall_getObjectTypeId(void) { return 0x0; }
int barrelpad_getExtraSize(void);
int barrelpad_getObjectTypeId(void);
int cf_doorlight_getExtraSize(void);
int cf_doorlight_getObjectTypeId(void);

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3EE8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3F00;
extern f32 lbl_803E3F04;
extern f32 lbl_803E3F08;
extern f32 lbl_803E3F0C;
extern f32 lbl_803E3F10;
extern f32 lbl_803E3F14;
extern f32 lbl_803E3F18;
extern f32 lbl_803E3F1C;
extern f32 lbl_803E3F20;
extern f32 lbl_803E3F24;
void cflightwall_render(void) { objRenderFn_8003b8f4(lbl_803E3EE8); }
void barrelpad_render(void);

void barrelpad_update(s16* obj);

void barrelpad_init(s16* obj, u8* def);

extern f32 lbl_803E3EEC;
extern f32 lbl_803E3EF0;

void cflightwall_init(s16* obj, u8* def)
{
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)def[0x18] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)def[0x19] << 8);
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x1a] << 8);
    if (def[0x1b] != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)
        def[0x1b] / lbl_803E3EEC;
        if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E3EF0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3EE8;
        }
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * *(f32*)((char*)*(int**)&((
            GameObject*)obj)->anim.modelInstance + 4);
    }
    ((GameObject*)obj)->objectFlags |= 0xA000;
}

void cf_doorlight_update(int obj);

void cf_doorlight_init(int* obj, s8* def);
