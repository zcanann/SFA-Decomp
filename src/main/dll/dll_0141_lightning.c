/* === moved from main/dll/MMP/MMP_asteroid.c [801978A0-801978A8) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/effect_interfaces.h"











extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();

extern EffectInterface** gPartfxInterface;
extern f32 lbl_803DC074;

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
extern f32 timeDelta;


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
int lightning_getExtraSize(void) { return 0x28; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4048;
extern void objRenderFn_8003b8f4(f32);



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



typedef struct LightningPlacement
{
    u8 pad0[0x14 - 0x0];
    u32 unk14;
    u32 unk18;
    u8 pad1C[0x22 - 0x1C];
    u16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} LightningPlacement;


typedef struct SfxplayerObjPlacement
{
    u8 pad0[0x14 - 0x0];
    u32 unk14;
    u32 unk18;
    u8 pad1C[0x22 - 0x1C];
    u16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} SfxplayerObjPlacement;


typedef struct WaterFallSprayState
{
    u32 unk0;
    u32 unk4;
} WaterFallSprayState;


extern void* ObjGroup_GetObjects();
extern undefined4 objInterpretSeq();

extern f32 lbl_803E4088;
extern f32 lbl_803E408C;
extern f32 lbl_803E4090;
extern f32 lbl_803E40A0;
extern f32 lbl_803E40B8;
extern f32 lbl_803E40C8;
extern f32 lbl_803E40CC;
extern f32 lbl_803E40D8;

extern u8* Obj_GetPlayerObject(void);
extern f32 sqrtf(f32 value);
extern f32 mathSinf(f32 angle);
extern f32 mathCosf(f32 angle);
extern int getCurSeqNo(void);
extern void PSMTXMultVec(f32 * mtx, f32 * in, f32 * out);
extern void OSReport(const char* fmt, ...);
extern const char sMoonrockTriggerIdentFormat[];

#define MOONROCK_ANGLE_TO_RADIANS(angle) ((lbl_803E40C8 * (f32)(s32)(-(angle))) / lbl_803E40CC)

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
extern void mm_free(void* p);

void lightning_free(u8* obj, int p2)
{
    u8* state = ((GameObject*)obj)->extra;
    void* h;
    ObjGroup_RemoveObject(obj, MMP_LIGHTNING_OBJGROUP);
    h = *(void**)state;
    if (h != NULL)
    {
        mm_free(h);
    }
}

/* lightning_render: deref obj->_b8->_0 (effect handle); if non-null call
 * lightningRender(handle). */
extern void lightningRender(u32 handle);

void lightning_render(u8* obj)
{
    u32 handle = *(u32*)(((GameObject*)obj)->extra);
    if (handle != 0)
    {
        lightningRender(handle);
    }
}

extern int lightningCreate(float* start, float* end, f32 radiusX, f32 radiusY, int delay,
                           int param_6, int param_7);
extern void hitDetectFn_80097070(u8* obj, double radius, int param_3, int param_4, int param_5,
                                 int param_6);
extern void objfx_spawnDirectionalBurst(u8* obj, int param_2, double radius, int param_4, int param_5,
                                        int param_6, double scale, int param_8, int param_9);

typedef struct LightningFlags
{
    u8 enabled : 1; /* 0x80 */
    u8 noAge : 1; /* 0x40 */
    u8 style : 1; /* 0x20 */
    u8 pad : 5;
} LightningFlags;

typedef struct LightningMode
{
    u8 pad : 4;
    u8 mode : 4; /* 0x0f */
} LightningMode;

void lightning_update(u8* obj)
{
    u8* state;
    u8* data;
    u32* objects;
    u8* otherState;
    int objectCount;
    int objectIndex;
    int spawnLightning;
    int handle;

    state = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((LightningPlacement*)data)->unk24 != -1)
    {
        if (((LightningFlags*)(state + 0x25))->enabled)
        {
            if (GameBit_Get(((LightningPlacement*)data)->unk24) == 0)
            {
                ((LightningFlags*)(state + 0x25))->enabled = 0;
                if (*(u32*)state != 0)
                {
                    mm_free(*(void**)state);
                    *(u32*)state = 0;
                }
            }
        }
        else if (GameBit_Get(((LightningPlacement*)data)->unk24) != 0)
        {
            ((LightningFlags*)(state + 0x25))->enabled = 1;
        }
    }

    if (*(u32*)state == 0 && ((LightningFlags*)(state + 0x25))->enabled)
    {
        spawnLightning = 0;
        ((MmpMoonrockState*)state)->homeX -= timeDelta;
        if (((MmpMoonrockState*)state)->homeX <= lbl_803E4088)
        {
            ((MmpMoonrockState*)state)->homeX += (f32)(s32)((u32)data[0x23] * 0x3c);
            spawnLightning = 1;
        }
        if (spawnLightning != 0)
        {
            objects = (u32*)ObjGroup_GetObjects(MMP_LIGHTNING_OBJGROUP, &objectCount);
            objectIndex = 0;
            while (objectIndex < objectCount)
            {
                u32 linkedHandle = *(u32*)(*(u32*)(objects[objectIndex] + 0x4c) + 0x14);
                if (linkedHandle == *(u32*)&((MmpMoonrockState*)state)->homeZ)
                {
                    break;
                }
                objectIndex++;
            }
            if (objectIndex == objectCount)
            {
                ((LightningFlags*)(state + 0x25))->enabled = 0;
                return;
            }

            handle = lightningCreate((float*)(obj + 0x0c), (float*)(objects[objectIndex] + 0x0c),
                                     *(f32*)(state + 0x08), ((MmpMoonrockState*)state)->baseY,
                                     (u16)(state[0x1c] + randomGetRange(-5, 5)), state[0x1d],
                                     ((LightningFlags*)(state + 0x25))->style ? 1 : 0);
            *(int*)state = handle;
            *(f32*)(state + 0x04) = lbl_803E4088;
            if ((((LightningMode*)(state + 0x24))->mode & 1) != 0)
            {
                hitDetectFn_80097070(obj, ((MmpMoonrockState*)state)->baseY2, 1, 7, 0x1e, 0);
            }
            otherState = *(u8**)(objects[objectIndex] + 0xb8);
            if ((((LightningMode*)(otherState + 0x24))->mode & 1) != 0)
            {
                hitDetectFn_80097070((u8*)objects[objectIndex], *(f32*)(otherState + 0x10), 1, 7,
                                     0x1e, 0);
            }
            if ((((LightningMode*)(state + 0x24))->mode & 2) != 0)
            {
                objfx_spawnDirectionalBurst(obj, 5, ((MmpMoonrockState*)state)->respawnTimer, 1, 1, 100, lbl_803E408C,
                                            0, 0);
            }
            if ((((LightningMode*)(otherState + 0x24))->mode & 2) != 0)
            {
                objfx_spawnDirectionalBurst((u8*)objects[objectIndex], 5, *(f32*)(otherState + 0x14),
                                            1, 1, 100, lbl_803E408C, 0, 0);
            }
        }
    }

    if (*(u32*)state != 0)
    {
        if (((LightningFlags*)(state + 0x25))->noAge == 0)
        {
            *(f32*)(state + 0x04) += timeDelta;
            *(u16*)(*(u32*)state + 0x20) = (u16)(int)(lbl_803E4090 + *(f32*)(state + 0x04));
        }
        if (*(u16*)(*(u32*)state + 0x20) >= *(u16*)(*(u32*)state + 0x22))
        {
            mm_free(*(void**)state);
            *(u32*)state = 0;
        }
    }
}

void lightning_init(u8* obj, u8* data)
{
    u8* state;
    f32 defaultScale;

    state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, MMP_LIGHTNING_OBJGROUP);
    ((LightningMode*)(state + 0x24))->mode = data[0x21];
    defaultScale = lbl_803E40A0;
    ((MmpMoonrockState*)state)->baseY2 = defaultScale;
    ((MmpMoonrockState*)state)->respawnTimer = defaultScale;
    *(f32*)(state + 0x08) = (f32)(u32)
    data[0x1c];
    ((MmpMoonrockState*)state)->baseY = (f32)(u32)
    data[0x1d];
    state[0x1c] = data[0x1e];
    state[0x1d] = data[0x1f];
    *(u32*)&((MmpMoonrockState*)state)->homeZ = *(u32*)(data + 0x18);

    ((LightningFlags*)(state + 0x25))->enabled = (data[0x20] & 1) ? 1 : 0;
    ((LightningFlags*)(state + 0x25))->style = (data[0x20] & 2) ? 1 : 0;
    ((LightningFlags*)(state + 0x25))->noAge = (data[0x20] & 4) ? 1 : 0;

    ((MmpMoonrockState*)state)->homeX = (f32)(s32)((u32)data[0x22] * 0x3c);
}

void WaterFallSpray_free(u8* obj);

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

void WaterFallSpray_update(int* objParam);

/* WaterFallSpray_init: stash 3 signed-byte<<8 fields at obj+0..+4, clear
 * obj+0xf4, install WaterFallSpray_SeqFn as the think routine at obj+0xbc, then
 * pick one of two SFX-id pairs based on the range of obj->_4c->_14. */
void WaterFallSpray_init(u8* obj, u8* data);

/* sfxplayerObj_init: prime obj->_b0 with SFXPLAYER_OBJECT_FLAGS, then dispatch
 * on (s8)data->_1d: gamebit mode stores GameBit_Get(data->_18) at sub[0] if the
 * event id is positive; random-delay mode computes randomGetRange(data->_1e, data->_1f)
 * scaled by lbl_803E40BC as f32; cases 1 and >=3 are no-ops. */
extern f32 lbl_803E40BC;

void sfxplayerObj_init(u8* obj, u8* data);

/* sfxplayerObj_free: bit-0 of obj->_b8->_4 gates teardown. When set, clear
 * it and stop two sfx loops (data->_1a and data->_22). Mode depends on
 * data->_1d: 1 → Sfx_RemoveLoopedObjectSound, else Sfx_StopFromObject. */
extern void Sfx_RemoveLoopedObjectSound(u8* obj, u16 sfx);
extern void Sfx_StopFromObject(u8* obj, u16 sfx);
extern void Sfx_AddLoopedObjectSound(u8* obj, u16 sfx);
extern void Sfx_PlayFromObject(u8* obj, u16 sfx);
extern void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u8* obj, u16 sfx);

void sfxplayerObj_free(u8* obj);

#define SFXPLAYER_START_SOUND(sfxExpr) \
    do { \
        soundId = (sfxExpr); \
        if (soundId != 0) { \
            soundObj = obj; \
            state[4] = state[4] | SFXPLAYER_RUNTIME_ACTIVE_FLAG; \
            if ((data[0x1c] & 0x10) == 0) { \
                soundObj = NULL; \
            } \
            if (soundObj == NULL || (data[0x1c] & 1) != 0) { \
                if (data[0x1d] == SFXPLAYER_MODE_LOOPED) { \
                    Sfx_AddLoopedObjectSound(soundObj, soundId); \
                } \
                else { \
                    Sfx_PlayFromObject(soundObj, soundId); \
                } \
            } \
            else { \
                Sfx_PlayAtPositionFromObject(*(f32 *)(soundObj + 0x0c), \
                                             *(f32 *)(soundObj + 0x10), \
                                             *(f32 *)(soundObj + 0x14), soundObj, soundId); \
            } \
        } \
    } while (0)

#define SFXPLAYER_STOP_PAIR() \
    do { \
        if (data[0x1d] == SFXPLAYER_MODE_LOOPED) { \
            soundId = *(u16 *)(data + 0x1a); \
            if (soundId != 0) { \
                Sfx_RemoveLoopedObjectSound(obj, soundId); \
            } \
            soundId = *(u16 *)(data + 0x22); \
            if (soundId != 0) { \
                Sfx_RemoveLoopedObjectSound(obj, soundId); \
            } \
        } \
        else { \
            soundId = *(u16 *)(data + 0x1a); \
            if (soundId != 0) { \
                Sfx_StopFromObject(obj, soundId); \
            } \
            soundId = *(u16 *)(data + 0x22); \
            if (soundId != 0) { \
                Sfx_StopFromObject(obj, soundId); \
            } \
        } \
    } while (0)

void sfxplayerObj_update(u8* obj);

void fn_80198A00(u8* obj, int seqArg);

int fn_80198B68(u8* obj, f32* point);

void fn_80198DE8(u8* obj, int seqArg);

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
void WaterFallSpray_render(void);

/* 8b "li r3, N; blr" returners. */
int WaterFallSpray_getExtraSize(void);
int sfxplayerObj_getExtraSize(void);

int WaterFallSpray_SeqFn(int* obj);
