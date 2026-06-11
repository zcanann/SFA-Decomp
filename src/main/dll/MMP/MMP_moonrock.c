#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/dll/MMP/MMP_moonrock.h"
#include "main/camera_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"

typedef struct WaterFallSprayPlacement
{
    u8 pad0[0x14 - 0x0];
    u32 unk14;
    u32 unk18;
    u8 pad1C[0x22 - 0x1C];
    u16 unk22;
    u8 pad24[0x28 - 0x24];
} WaterFallSprayPlacement;


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


extern undefined4 FUN_80006810();
extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017814();
extern int FUN_80017a98();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_80048000();
extern undefined4 FUN_8004800c();
extern int FUN_8007f7c0();
extern undefined4 FUN_80081028();
extern uint FUN_80081030();
extern undefined4 FUN_800810ec();
extern undefined4 FUN_800810f4();
extern undefined4 objInterpretSeq();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e4d18;
extern f64 DOUBLE_803e4d30;
extern f64 DOUBLE_803e4d40;
extern f64 DOUBLE_803e4d48;
extern f64 DOUBLE_803e4d58;
extern f32 lbl_803DC074;
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E4088;
extern f32 lbl_803E408C;
extern f32 lbl_803E4090;
extern f32 lbl_803E40A0;
extern f64 lbl_803E40B0;
extern f32 lbl_803E40B8;
extern f32 lbl_803E40C8;
extern f32 lbl_803E40CC;
extern f64 lbl_803E40D0;
extern f32 lbl_803E40D8;
extern f32 lbl_803E4D00;
extern f32 lbl_803E4D04;
extern f32 lbl_803E4D08;
extern f32 lbl_803E4D0C;
extern f32 lbl_803E4D10;
extern f32 lbl_803E4D14;
extern f32 lbl_803E4D20;
extern f32 lbl_803E4D24;
extern f32 lbl_803E4D28;
extern f32 lbl_803E4D38;
extern f32 lbl_803E4D50;
extern f32 lbl_803E4D54;

extern EffectInterface** gPartfxInterface;
extern u8* Obj_GetPlayerObject(void);
extern f32 sqrtf(f32 value);
extern f32 mathSinf(f32 angle);
extern f32 mathCosf(f32 angle);
extern int getCurSeqNo(void);
extern void Sfx_KeepAliveLoopedObjectSound(u8* obj, int sfxId);
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

void sfxplayerObj_init(u8* obj, u8* data)
{
    u8* sub = ((GameObject*)obj)->extra;
    int type;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | SFXPLAYER_OBJECT_FLAGS);
    type = data[0x1d];
    switch (type)
    {
    case SFXPLAYER_MODE_GAMEBIT:
        {
            s16 bit = *(s16*)(data + 0x18);
            if (bit > 0)
            {
                *(int*)sub = GameBit_Get(bit);
            }
            break;
        }
    case SFXPLAYER_MODE_LOOPED:
        break;
    case SFXPLAYER_MODE_RANDOM_DELAY:
        {
            int v = randomGetRange(data[0x1e], data[0x1f]);
            *(f32*)sub = (f32)v * lbl_803E40BC;
            break;
        }
    }
}

/* sfxplayerObj_free: bit-0 of obj->_b8->_4 gates teardown. When set, clear
 * it and stop two sfx loops (data->_1a and data->_22). Mode depends on
 * data->_1d: 1 → Sfx_RemoveLoopedObjectSound, else Sfx_StopFromObject. */
extern void Sfx_RemoveLoopedObjectSound(u8* obj, u16 sfx);
extern void Sfx_StopFromObject(u8* obj, u16 sfx);
extern void Sfx_AddLoopedObjectSound(u8* obj, u16 sfx);
extern void Sfx_PlayFromObject(u8* obj, u16 sfx);
extern void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u8* obj, u16 sfx);

void sfxplayerObj_free(u8* obj)
{
    u8* data = *(u8**)&((GameObject*)obj)->anim.placementData;
    u8* sub = ((GameObject*)obj)->extra;
    u8 flag = sub[4];
    if ((flag & SFXPLAYER_RUNTIME_ACTIVE_FLAG) == 0) return;
    sub[4] = (u8)(flag & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG);
    if (data[0x1d] == SFXPLAYER_MODE_LOOPED)
    {
        u16 sfx1 = *(u16*)(data + 0x1a);
        if (sfx1 != 0) Sfx_RemoveLoopedObjectSound(obj, sfx1);
        {
            u16 sfx2 = ((SfxplayerObjPlacement*)data)->unk22;
            if (sfx2 != 0) Sfx_RemoveLoopedObjectSound(obj, sfx2);
        }
    }
    else
    {
        u16 sfx1 = *(u16*)(data + 0x1a);
        if (sfx1 != 0) Sfx_StopFromObject(obj, sfx1);
        {
            u16 sfx2 = ((SfxplayerObjPlacement*)data)->unk22;
            if (sfx2 != 0) Sfx_StopFromObject(obj, sfx2);
        }
    }
}

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

void sfxplayerObj_update(u8* obj)
{
    u8* state;
    u8* data;
    u8* focusObj;
    u8* soundObj;
    u16 soundId;
    int bitState;

    state = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    if ((data[0x1c] & 8) != 0)
    {
        if (getCurSeqNo() != 0)
        {
            focusObj = (*gCameraInterface)->getCamera();
            ((void (*)(f32, f32, f32, int, int, u8*, u8*, u8*))(*gRomCurveInterface)->slot20)(
                *(f32*)(focusObj + 0x18), *(f32*)(focusObj + 0x1c), *(f32*)(focusObj + 0x20),
                7, (s8)data[0x20], obj + 0x0c, obj + 0x10, obj + 0x14);
        }
        else
        {
            focusObj = Obj_GetPlayerObject();
            ((void (*)(f32, f32, f32, int, int, u8*, u8*, u8*))(*gRomCurveInterface)->slot20)(
                *(f32*)(focusObj + 0x18), *(f32*)(focusObj + 0x1c), *(f32*)(focusObj + 0x20),
                7, (s8)data[0x20], obj + 0x0c, obj + 0x10, obj + 0x14);
        }
    }

    if (*(s16*)(data + 0x18) > 0)
    {
        bitState = GameBit_Get(*(s16*)(data + 0x18));
    }

    switch (data[0x1d])
    {
    case SFXPLAYER_MODE_GAMEBIT:
        if (*(s16*)(data + 0x18) > 0)
        {
            if (*(int*)state != 0)
            {
                if (bitState == 0)
                {
                    *(u32*)state = 0;
                    if ((data[0x1c] & 4) != 0)
                    {
                        SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                        SFXPLAYER_START_SOUND(((SfxplayerObjPlacement *)data)->unk22);
                    }
                }
            }
            else if (bitState != 0)
            {
                *(u32*)state = 1;
                if ((data[0x1c] & 2) != 0)
                {
                    SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                    SFXPLAYER_START_SOUND(((SfxplayerObjPlacement *)data)->unk22);
                }
            }
        }
        break;
    case SFXPLAYER_MODE_LOOPED:
        if ((*(s16*)(data + 0x18) == -1) ||
            (((data[0x1c] & 2) != 0) && (bitState != 0)) ||
            (((data[0x1c] & 4) != 0) && (bitState == 0)))
        {
            if ((state[4] & SFXPLAYER_RUNTIME_ACTIVE_FLAG) == 0)
            {
                SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                SFXPLAYER_START_SOUND(((SfxplayerObjPlacement *)data)->unk22);
            }
        }
        else if ((state[4] & SFXPLAYER_RUNTIME_ACTIVE_FLAG) != 0)
        {
            state[4] = state[4] & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG;
            SFXPLAYER_STOP_PAIR();
        }
        break;
    case 2:
        if ((*(s16*)(data + 0x18) == -1) ||
            (((data[0x1c] & 2) != 0) && (bitState != 0)) ||
            (((data[0x1c] & 4) != 0) && (bitState == 0)))
        {
            *(f32*)state -= lbl_803DC074;
            if (*(f32*)state <= lbl_803E40B8)
            {
                *(f32*)state = (f32)(s32)
                randomGetRange(data[0x1e], data[0x1f]) * lbl_803E40BC;
                SFXPLAYER_START_SOUND(*(u16 *)(data + 0x1a));
                SFXPLAYER_START_SOUND(((SfxplayerObjPlacement *)data)->unk22);
            }
        }
        else if ((state[4] & SFXPLAYER_RUNTIME_ACTIVE_FLAG) != 0)
        {
            state[4] = state[4] & ~SFXPLAYER_RUNTIME_ACTIVE_FLAG;
            SFXPLAYER_STOP_PAIR();
        }
        break;
    }
}

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
void WaterFallSpray_render(void)
{
}

/* 8b "li r3, N; blr" returners. */
int WaterFallSpray_getExtraSize(void) { return 0x8; }
int sfxplayerObj_getExtraSize(void) { return 0x8; }

int WaterFallSpray_SeqFn(int* obj)
{
    WaterFallSpray_update(obj);
    return 0;
}
