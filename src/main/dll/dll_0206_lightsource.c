/* DLL 0x0206 (lightsource) — Light source and Arwing attachment objects [0x801F33B4-0x801F3C2C). */
#include "main/audio/sfx_ids.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/LGT/dll_0206_lightsource.h"
#include "main/objhits.h"

typedef struct LightsourceState
{
    u8 pad0[0x4C - 0x0];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 pad2F9[0x300 - 0x2F9];
} LightsourceState;

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* lightsource_getExtraSize == 0x1c.  LightSourceState lives in the shared
 * LGTpointlight header (same 0x206 DLL); this fragment's 0x0C timer is the
 * header's unk0C field. */

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006ba8();
extern uint FUN_80006c00();
extern undefined4 FUN_8001771c();
extern uint FUN_80017a98();
extern undefined4 ObjMsg_SendToObject();
extern int FUN_800632f4();

extern f32 lbl_803DC074;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E6A20;
extern f32 lbl_803E6A24;
extern f32 lbl_803E6A80;

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 timeDelta;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5E08;
extern void queueGlowRender(void* light);
extern int GameBit_Get(int id);
extern int Obj_GetPlayerObject(void);
extern void ModelLightStruct_free(void* light);
extern void GameBit_Set(int slot, int val);
extern void* objCreateLight(void* obj, int);
extern void modelLightStruct_setLightKind(void*, int);
extern void modelLightStruct_setPosition(f32, f32, f32);
extern void modelLightStruct_setDiffuseColor(void*, u8, u8, u8, int);
extern void modelLightStruct_setSpecularColor(void*, u8, u8, u8, int);
extern void modelLightStruct_setDistanceAttenuation(void*, f32, f32);
extern void modelLightStruct_setEnabled(void*, int, f32);
extern void modelLightStruct_startColorFade(void*, int, int);
extern void modelLightStruct_setDiffuseTargetColor(void*, int, int, int, int);
extern void lightSetField4D(void*, int);
extern void modelLightStruct_setupGlow(void*, int, u8, u8, u8, int, f32);
extern void modelLightStruct_setGlowProjectionRadius(void*, f32);
extern u8 lbl_802C2488[];
extern f32 lbl_803E5E0C;
extern f32 lbl_803E5E10;
extern f32 lbl_803E5E20;
extern f32 lbl_803E5E24;
extern f32 lbl_803E5E28;
extern f32 lbl_803E5E2C;
extern f32 lbl_803E5E30;
extern f32 lbl_803E5E34;
extern f32 lbl_803E5E38;
extern f32 lbl_803E5E3C;
extern f32 lbl_803E5E40;

void FUN_801f1634(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    char hitCount;
    float surfaceY;
    float fadeRange;
    float landVelY;
    int iface;
    u8 activated;
    float* hit;
    uint flags;
    int hitOff;
    float landedSurface;
    int hitIdx;
    undefined2* state;
    int hitList[3];

    state = ((GameObject*)param_9)->extra;
    iface = FUN_80017a98();
    if (*(char*)((int)state + 5) == '\0')
    {
        activated = 0;
        if (((*(byte*)&((GameObject*)param_9)->anim.resetHitboxMode & 1) != 0) && (((GameObject*)param_9)->unkF8 == 0))
        {
            *state = 0;
            state[1] = 0x28;
            FUN_80006ba8(0, 0x100);
            activated = 1;
        }
        *(u8*)((int)state + 5) = activated;
        if (*(char*)((int)state + 5) != '\0')
        {
            *(u8*)(state + 3) = 1;
        }
        if (((GameObject*)param_9)->unkF8 == 0)
        {
            ObjHits_EnableObject(param_9);
            *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.
                resetHitboxMode & 0xf7;
            ((GameObject*)param_9)->anim.velocityY = -(lbl_803E6A1C * lbl_803DC074 - ((GameObject*)param_9)->anim.
                velocityY);
            ((GameObject*)param_9)->anim.localPosY =
                ((GameObject*)param_9)->anim.velocityY * lbl_803DC074 + ((GameObject*)param_9)->anim.localPosY;
            iface = FUN_800632f4((double)((GameObject*)param_9)->anim.localPosX,
                                 (double)((GameObject*)param_9)->anim.localPosY,
                                 (double)((GameObject*)param_9)->anim.localPosZ, param_9, hitList, 0, 1);
            landVelY = lbl_803E6A24;
            fadeRange = lbl_803E6A20;
            landedSurface = 0.0;
            hitIdx = 0;
            hitOff = 0;
            if (0 < iface)
            {
                do
                {
                    hit = *(float**)(hitList[0] + hitOff);
                    if (*(char*)(hit + 5) != '\x0e')
                    {
                        surfaceY = *hit;
                        if ((((GameObject*)param_9)->anim.localPosY < surfaceY) &&
                            ((surfaceY - fadeRange < ((GameObject*)param_9)->anim.localPosY || (hitIdx == 0))))
                        {
                            landedSurface = hit[4];
                            ((GameObject*)param_9)->anim.localPosY = surfaceY;
                            ((GameObject*)param_9)->anim.velocityY = landVelY;
                        }
                    }
                    hitOff = hitOff + 4;
                    hitIdx = hitIdx + 1;
                    iface = iface + -1;
                }
                while (iface != 0);
            }
            if (landedSurface != 0.0)
            {
                iface = *(int*)((int)landedSurface + 0x58);
                hitCount = *(char*)(iface + 0x10f);
                *(char*)(iface + 0x10f) = hitCount + '\x01';
                *(uint*)(iface + hitCount * 4 + 0x100) = param_9;
            }
        }
    }
    else
    {
        ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        flags = FUN_80006c00(0);
        if ((flags & 0x100) != 0)
        {
            *(u8*)(state + 3) = 0;
            FUN_80006ba8(0, 0x100);
        }
        if (((GameObject*)param_9)->unkF8 == 1)
        {
            *(u8*)((int)state + 5) = 2;
        }
        if ((*(char*)((int)state + 5) == '\x02') && (((GameObject*)param_9)->unkF8 == 0))
        {
            *(u8*)((int)state + 5) = 0;
            *(u8*)(state + 3) = 0;
        }
        if (*(char*)(state + 3) != '\0')
        {
            ObjMsg_SendToObject(iface, 0x100008, param_9, CONCAT22(state[1], *state));
        }
    }
    return;
}

void FUN_801f2b94(short* obj)
{
    int iface;
    double dist;

    if (*(char*)(*(int*)(obj + 0x5c) + 0xc) == '\x02')
    {
        *obj = *obj + 0x32;
    }
    iface = FUN_80017a98();
    dist = (double)FUN_8001771c((float*)(iface + 0x18), (float*)(obj + 0xc));
    if ((double)lbl_803E6A80 <= dist)
    {
        FUN_8000680c((int)obj, 0x40);
    }
    else
    {
        FUN_80006824((uint)obj,SFXmn_eggylaugh216);
    }
    return;
}

void lightsource_hitDetect(void)
{
}

int dll_1FF_getExtraSize_ret_8(void);
int lightsource_getExtraSize(void) { return 0x1c; }
int lightsource_getObjectTypeId(void) { return 0x1; }

void lightsource_render(void* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderFn_8003b8f4(void* obj, int p1, int p2, int p3, int p4, f32 alpha);
    void* light = (*(LightSourceState**)&((GameObject*)obj)->extra)->light;
    if (light != NULL && ((LightsourceState*)light)->unk2F8 != 0 && ((LightsourceState*)light)->unk4C != 0)
    {
        queueGlowRender(light);
    }
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5E08);
    }
}

int dll_1FF_getObjectTypeId(int* obj);

void lightsource_free(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (((LightSourceState*)state)->light != 0)
    {
        ModelLightStruct_free(((LightSourceState*)state)->light);
    }
}

/* dll_1FF_render: when obj->_f8 implies
 * visible == -1 (else visible != 0), toggle bit 0x1000 of obj->_64->_30
 * based on obj->_b4 == -1, then call objRenderFn_8003b8f4. */

void dll_1FF_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);

/* dll_200_render: when visible != 0 and
 * gMapEventInterface vtable[0x40] applied to obj->_ac returns 4, gate on
 * GameBit_Get(0x2bd); else render directly via objRenderFn_8003b8f4. */

/* dll_200_init: write a function pointer
 * (dll_200_SeqFn) into obj->_bc and prime obj->_b8 (the body block) with
 * fixed bytes, the three float position-quaternion from arg+8/c/10,
 * GameBit_Get(0xd0) latched into b->_24, plus several literal latches. */

#pragma opt_strength_reduction off

#pragma opt_strength_reduction off

typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

void lightsource_update(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int id);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_AddLoopedObjectSound(int obj, int sfx);
    extern void Sfx_RemoveLoopedObjectSound(int obj, int sfx);
    extern void fn_80098B18(int obj, f32 scale, u8 a, u8 b, int c, f32* vec);
    extern f32 timeDelta;
    extern f32 lbl_803E5E08;
    extern f32 lbl_803E5E0C;
    extern f32 lbl_803E5E10;
    extern f32 lbl_803E5E14;
    extern f32 lbl_803E5E18;
    extern f32 lbl_803E5E1C;
    LightSourceState* b;
    char* t;
    s16 sum;
    u8 sfxFlag;
    f32 vec[3];
    struct
    {
        u8 pad[8];
        f32 scale;
        u8 pad2[0xc];
    } fx;

    b = ((GameObject*)obj)->extra;
    switch (b->mode)
    {
    case 0:
        break;
    case 1:
        b->litPrev = b->lit;
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
        {
            b->lit = (u8)(1 - b->lit);
        }
        if (b->lit != b->litPrev)
        {
            if (b->lit != 0)
            {
                if (b->gameBit != -1 && GameBit_Get(b->gameBit) == 0)
                {
                    GameBit_Set(b->gameBit, 1);
                }
                Sfx_PlayFromObject(obj, 0x80);
            }
            else
            {
                (*gExpgfxInterface)->freeSource(obj);
                if (b->gameBit != -1 && GameBit_Get(b->gameBit) != 0)
                {
                    GameBit_Set(b->gameBit, 0);
                }
            }
        }
        break;
    }
    if (b->lit != 0 && (((GameObject*)obj)->objectFlags & 0x800))
    {
        b->fxTimer = b->fxTimer - timeDelta;
        if (b->fxTimer <= lbl_803E5E0C)
        {
            sfxFlag = b->fxArg;
            b->fxTimer = b->fxTimer + lbl_803E5E10;
        }
        else
        {
            sfxFlag = 0;
        }
        if (b->fxType != 0 || b->fxArg != 0)
        {
            vec[0] = lbl_803E5E0C;
            if (((GameObject*)obj)->anim.seqId == 0x717)
            {
                vec[1] = vec[0];
            }
            else
            {
                vec[1] = lbl_803E5E14;
            }
            vec[2] = lbl_803E5E0C;
            fn_80098B18(obj, lbl_803E5E18 * ((GameObject*)obj)->anim.rootMotionScale, b->fxType, sfxFlag, 0, vec);
        }
        if (b->sparks != 0)
        {
            b->unk0C = b->unk0C - timeDelta;
            if (b->unk0C <= lbl_803E5E0C)
            {
                fx.scale = lbl_803E5E08;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7cb, &fx, 2, -1, NULL);
                b->unk0C = b->unk0C + lbl_803E5E1C;
            }
        }
    }
    t = (char*)b->light;
    if (t != NULL && *(u8*)(t + 0x2f8) != 0 && *(u8*)(t + 0x4c) != 0)
    {
        sum = (s16)(*(u8*)(t + 0x2f9) + *(s8*)(t + 0x2fa));
        if (sum < 0)
        {
            sum = 0;
            *(u8*)(t + 0x2fa) = 0;
        }
        else if (sum > 255)
        {
            sum = 255;
            *(u8*)(t + 0x2fa) = 0;
        }
        *(u8*)((char*)b->light + 0x2f9) = (u8)sum;
    }
    if (((GameObject*)obj)->anim.seqId != 0x705 && ((GameObject*)obj)->anim.seqId != 0x712)
    {
        if (b->lit != 0)
        {
            if (!((LightSourceFlagByte*)&b->loopFlags)->looped)
            {
                Sfx_AddLoopedObjectSound(obj, 0x72);
                ((LightSourceFlagByte*)&b->loopFlags)->looped = 1;
            }
        }
        else
        {
            if (((LightSourceFlagByte*)&b->loopFlags)->looped)
            {
                Sfx_RemoveLoopedObjectSound(obj, 0x72);
                ((LightSourceFlagByte*)&b->loopFlags)->looped = 0;
            }
        }
    }
}

#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_strength_reduction reset
#pragma opt_strength_reduction reset

typedef struct LightColorTable
{
    u8 c[45];
} LightColorTable;

void lightsource_init(GameObject* obj, LightSourceSetup* setup)
{
    LightSourceState* state;
    LightColorTable colors;
    int flags;
    int range;
    int colorBase;

    state = obj->extra;
    colors = *(LightColorTable*)lbl_802C2488;
    obj->anim.rotX = (s16)(((int)setup->yaw & 0x3fU) << 10);
    range = setup->range;
    if (range > 0)
    {
        obj->anim.rootMotionScale = (f32)range / lbl_803E5E20;
    }
    else
    {
        obj->anim.rootMotionScale = lbl_803E5E24;
    }

    state->mode = setup->mode;
    state->gameBit = setup->gameBit;
    state->fxType = 1;
    if (setup->flags & LIGHTSOURCE_FLAG_FX_ARG_ZERO)
    {
        state->fxArg = 0;
    }
    else
    {
        state->fxArg = 3;
    }
    if (setup->options & LIGHTSOURCE_OPTION_SPARKS)
    {
        state->sparks = 1;
    }
    else
    {
        state->sparks = 0;
    }

    switch (state->mode)
    {
    case 0:
        state->lit = 1;
        flags = setup->flags;
        if (flags & LIGHTSOURCE_FLAG_FX_TYPE_4)
        {
            state->fxType = 4;
        }
        else if (flags & LIGHTSOURCE_FLAG_FX_TYPE_8)
        {
            state->fxType = 8;
        }
        else if (flags & LIGHTSOURCE_FLAG_FX_TYPE_6)
        {
            state->fxType = 6;
        }
        else if (flags & LIGHTSOURCE_FLAG_FX_ARG_6)
        {
            state->fxArg = 6;
        }
        break;
    }

    if (setup->flags & LIGHTSOURCE_FLAG_CREATE_LIGHT)
    {
        if (state->light == NULL)
        {
            state->light = objCreateLight(obj, 1);
            if (state->light != NULL)
            {
                modelLightStruct_setLightKind(state->light, 2);
            }
        }
        if (state->light != NULL)
        {
            if (obj->anim.seqId == 0x705 || obj->anim.seqId == 0x712)
            {
                modelLightStruct_setPosition(lbl_803E5E0C, lbl_803E5E0C, lbl_803E5E0C);
            }
            else
            {
                modelLightStruct_setPosition(lbl_803E5E0C, lbl_803E5E28, lbl_803E5E0C);
            }

            colorBase = state->fxType * 3;
            modelLightStruct_setDiffuseColor(state->light, colors.c[colorBase], colors.c[colorBase + 1],
                                             colors.c[colorBase + 2], 0xff);
            colorBase = state->fxType * 3;
            modelLightStruct_setSpecularColor(state->light, colors.c[colorBase], colors.c[colorBase + 1],
                                              colors.c[colorBase + 2], 0xff);
            modelLightStruct_setDistanceAttenuation(state->light, lbl_803E5E2C, lbl_803E5E30);
            modelLightStruct_setEnabled(state->light, 1, lbl_803E5E0C);
            modelLightStruct_startColorFade(state->light, 1, 3);

            colorBase = state->fxType * 3;
            modelLightStruct_setDiffuseTargetColor(state->light, (int)(lbl_803E5E34 * (f32)(u32)colors.c[colorBase]),
                (int)
            (lbl_803E5E34 * (f32)(u32)
            colors.c[colorBase + 1]
            )
            ,
            (int)
            (lbl_803E5E34 * (f32)(u32)
            colors.c[colorBase + 2]
            )
            ,
            0xff
            )
            ;
            lightSetField4D(state->light, 1);

            if (setup->flags & LIGHTSOURCE_FLAG_CREATE_GLOW)
            {
                if (obj->anim.seqId == 0x705 || obj->anim.seqId == 0x712)
                {
                    colorBase = state->fxType * 3;
                    modelLightStruct_setupGlow(state->light, 0, colors.c[colorBase], colors.c[colorBase + 1],
                                               colors.c[colorBase + 2],
                                               0x8c, lbl_803E5E38 * (lbl_803E5E3C * obj->anim.rootMotionScale));
                }
                else
                {
                    colorBase = state->fxType * 3;
                    modelLightStruct_setupGlow(state->light, 0, colors.c[colorBase], colors.c[colorBase + 1],
                                               colors.c[colorBase + 2],
                                               0x8c, lbl_803E5E3C * obj->anim.rootMotionScale);
                }
                modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E5E40);
            }
        }
    }
    else
    {
        state->light = NULL;
    }

    if (setup->flags & LIGHTSOURCE_FLAG_DISABLE_FX_TYPE)
    {
        state->fxType = 0;
    }
    obj->objectFlags |= 0x2000;
    state->fxTimer = lbl_803E5E10;
    state->sparkTimer = lbl_803E5E08;
}

void lightsource_release(void)
{
}

void lightsource_initialise(void)
{
}

void wmworm_hitDetect(void);
