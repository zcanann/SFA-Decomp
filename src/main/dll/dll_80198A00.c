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
int lightning_getExtraSize(void);

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

void lightning_free(u8* obj, int p2);

/* lightning_render: deref obj->_b8->_0 (effect handle); if non-null call
 * lightningRender(handle). */
extern void lightningRender(u32 handle);

void lightning_render(u8* obj);

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

void lightning_update(u8* obj);

void lightning_init(u8* obj, u8* data);

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

void fn_80198A00(u8* obj, int seqArg)
{
    u8* state;
    f32 hitDistance;
    int queryType;
    int curveHit;
    int frontBlocked;
    int rearBlocked;

    queryType = 0x17;
    state = ((GameObject*)obj)->extra;
    curveHit = (*gRomCurveInterface)->find(&queryType, 1,
                                           *(s16*)(*(u8**)&((GameObject*)obj)->anim.placementData + 0x38),
                                           *(f32*)(state + 0x28), *(f32*)(state + 0x2c), *(f32*)(state + 0x30));
    frontBlocked = ((int (*)(int, f32, f32, f32, f32*))(*gRomCurveInterface)->slot4C)(
        curveHit, *(f32*)(state + 0x28), *(f32*)(state + 0x2c), *(f32*)(state + 0x30),
        &hitDistance);
    rearBlocked = ((int (*)(int, f32, f32, f32, f32*))(*gRomCurveInterface)->slot4C)(
        curveHit, ((MmpMoonrockState*)state)->homeY, ((MmpMoonrockState*)state)->homeZ, *(f32*)(state + 0x24),
        &hitDistance);

    if (frontBlocked != 0)
    {
        if (rearBlocked == 0)
        {
            objInterpretSeq(obj, seqArg, 1, (int)hitDistance);
        }
        else
        {
            objInterpretSeq(obj, seqArg, 2, (int)hitDistance);
        }
    }
    else if (rearBlocked != 0)
    {
        objInterpretSeq(obj, seqArg, -1, (int)hitDistance);
    }
    else
    {
        objInterpretSeq(obj, seqArg, -2, (int)hitDistance);
    }
}

int fn_80198B68(u8* obj, f32* point)
{
    u8* data;
    f32 pointX;
    f32 pointY;
    f32 pointZ;
    f32 yawCos;
    f32 yawSin;
    f32 pitchCos;
    f32 pitchSin;
    f32 relX;
    f32 relY;
    f32 relZ;
    f32 localX;
    f32 localY;
    f32 localZ;
    f32 forward;

    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    pointX = point[0];
    pointY = point[1];
    pointZ = point[2];

    yawCos = mathSinf(MOONROCK_ANGLE_TO_RADIANS(*(s16 *)obj));
    yawSin = mathCosf(MOONROCK_ANGLE_TO_RADIANS(*(s16 *)obj));
    pitchCos = mathSinf(MOONROCK_ANGLE_TO_RADIANS(((GameObject *)obj)->anim.rotY));
    pitchSin = mathCosf(MOONROCK_ANGLE_TO_RADIANS(((GameObject *)obj)->anim.rotY));

    relX = pointX - ((GameObject*)obj)->anim.worldPosX;
    relY = pointY - ((GameObject*)obj)->anim.worldPosY;
    relZ = pointZ - ((GameObject*)obj)->anim.worldPosZ;
    localX = relX * yawSin - relZ * yawCos;
    forward = relX * yawCos + relZ * yawSin;
    localY = relY * pitchSin - forward * pitchCos;
    localZ = relY * pitchCos + forward * pitchSin;

    if (localX < lbl_803E40D8)
    {
        localX = -localX;
    }
    if (localY < lbl_803E40D8)
    {
        localY = -localY;
    }
    if (localZ < lbl_803E40D8)
    {
        localZ = -localZ;
    }

    if ((localX <= (f32)(s32)(data[0x3a] << 1)) &&
        (localY <= (f32)(s32)(data[0x3b] << 1)) &&
        (localZ <= (f32)(s32)(data[0x3c] << 1)))
    {
        return 1;
    }
    return 0;
}

void fn_80198DE8(u8* obj, int seqArg)
{
    u8* data;
    u8* state;
    f32 planeBase;
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    f32 nearX;
    f32 nearY;
    f32 nearZ;
    f32 farX;
    f32 farY;
    f32 farZ;
    f32 prodY;
    f32 prodZ;
    f32 nearDist;
    f32 farDist;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 t;
    f32 localPos[3];
    s8 triggerState;

    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;

    planeBase = ((MmpMoonrockState*)state)->homeX;
    normalZ = ((MmpMoonrockState*)state)->respawnTimer;
    nearZ = *(f32*)(state + 0x24);
    prodZ = normalZ * nearZ;
    normalX = ((MmpMoonrockState*)state)->baseY;
    nearX = ((MmpMoonrockState*)state)->homeY;
    normalY = ((MmpMoonrockState*)state)->baseY2;
    nearY = ((MmpMoonrockState*)state)->homeZ;
    prodY = normalY * nearY;
    nearDist = planeBase + (prodZ + (normalX * nearX + prodY));
    farZ = *(f32*)(state + 0x30);
    farX = *(f32*)(state + 0x28);
    farY = *(f32*)(state + 0x2c);
    farDist = planeBase + (normalZ * farZ + (normalX * farX + normalY * farY));

    if (farDist < lbl_803E40D8)
    {
        triggerState = (nearDist < lbl_803E40D8) ? 2 : 1;
    }
    else
    {
        triggerState = (nearDist < lbl_803E40D8) ? -1 : -2;
    }

    if ((triggerState == 1) || (triggerState == -1))
    {
        deltaX = farX - nearX;
        deltaY = farY - nearY;
        deltaZ = farZ - nearZ;
        t = (((-normalX * nearX - prodY) - prodZ) - planeBase) /
            ((normalY * deltaY) + (normalX * deltaX) + (normalZ * deltaZ));

        localPos[0] = t * deltaX + nearX;
        localPos[1] = t * deltaY + ((MmpMoonrockState*)state)->homeZ;
        localPos[2] = t * deltaZ + *(f32*)(state + 0x24);
        PSMTXMultVec((f32*)(state + 0x38), localPos, localPos);

        if ((localPos[0] >= -*(f32*)(state + 0x34)) && (localPos[0] <= *(f32*)(state + 0x34)) &&
            (localPos[1] >= -*(f32*)(state + 0x34)) && (localPos[1] <= *(f32*)(state + 0x34)))
        {
            OSReport(sMoonrockTriggerIdentFormat, triggerState, *(u32*)(data + 0x14));
            objInterpretSeq(obj, seqArg, triggerState, (int)farDist);
        }
    }
}

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
