/* DLL 0x0206 (lightsource) — Light source and Arwing attachment objects [0x801F33B4-0x801F3C2C). */
#include "main/audio/sfx_ids.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/ARW/ARWarwingattachment.h"
#include "main/dll/LGT/dll_0206_lightsource.h"
#include "main/objHitReact.h"
#include "main/objseq.h"


typedef struct LightsourceState
{
    u8 pad0[0x4C - 0x0];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 pad2F9[0x300 - 0x2F9];
} LightsourceState;


/* Per-object extra state for the WM laser beam emitter. */


STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* pressureswitch_getExtraSize == 0x8. */

/* wmlasertarget_getExtraSize == 0x4. */

/* WM_colrise_getExtraSize == 0x4. */

/* wmtorch_getExtraSize == 0x10. */

/* lightsource_getExtraSize == 0x1c.  LightSourceState lives in the shared
 * LGTpointlight header (same 0x206 DLL); this fragment's 0x0C timer is the
 * header's unk0C field. */

/* dll_1FF_getExtraSize == 0x8 (grabbable hook). */

/* dll_200_getExtraSize == 0x28 (kid attachment actor). */


STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006ba8();
extern uint FUN_80006c00();
extern undefined4 FUN_8001771c();
extern uint FUN_80017a98();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjMsg_SendToObject();
extern int FUN_800632f4();

extern f32 lbl_803DC074;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E6A20;
extern f32 lbl_803E6A24;
extern f32 lbl_803E6A80;

/*
 * --INFO--
 *
 * Function: LaserBeam_update
 * EN v1.0 Address: 0x801F0B50
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801F0DA4
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801f1634
 * EN v1.0 Address: 0x801F1634
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x801F22BC
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1634(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    char cVar1;
    float fVar2;
    float fVar3;
    float fVar4;
    int iVar5;
    u8 uVar8;
    float* pfVar6;
    uint uVar7;
    int iVar9;
    float fVar10;
    int iVar11;
    undefined4 in_r7;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined2* puVar12;
    undefined8 uVar13;
    int local_18[3];

    puVar12 = ((GameObject*)param_9)->extra;
    iVar5 = FUN_80017a98();
    if (*(char*)((int)puVar12 + 5) == '\0')
    {
        uVar8 = 0;
        if (((*(byte*)&((GameObject*)param_9)->anim.resetHitboxMode & 1) != 0) && (((GameObject*)param_9)->unkF8 == 0))
        {
            *puVar12 = 0;
            puVar12[1] = 0x28;
            FUN_80006ba8(0, 0x100);
            uVar8 = 1;
        }
        *(u8*)((int)puVar12 + 5) = uVar8;
        if (*(char*)((int)puVar12 + 5) != '\0')
        {
            *(u8*)(puVar12 + 3) = 1;
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
            iVar5 = FUN_800632f4((double)((GameObject*)param_9)->anim.localPosX,
                                 (double)((GameObject*)param_9)->anim.localPosY,
                                 (double)((GameObject*)param_9)->anim.localPosZ, param_9, local_18, 0, 1);
            fVar4 = lbl_803E6A24;
            fVar3 = lbl_803E6A20;
            fVar10 = 0.0;
            iVar11 = 0;
            iVar9 = 0;
            if (0 < iVar5)
            {
                do
                {
                    pfVar6 = *(float**)(local_18[0] + iVar9);
                    if (*(char*)(pfVar6 + 5) != '\x0e')
                    {
                        fVar2 = *pfVar6;
                        if ((((GameObject*)param_9)->anim.localPosY < fVar2) &&
                            ((fVar2 - fVar3 < ((GameObject*)param_9)->anim.localPosY || (iVar11 == 0))))
                        {
                            fVar10 = pfVar6[4];
                            ((GameObject*)param_9)->anim.localPosY = fVar2;
                            ((GameObject*)param_9)->anim.velocityY = fVar4;
                        }
                    }
                    iVar9 = iVar9 + 4;
                    iVar11 = iVar11 + 1;
                    iVar5 = iVar5 + -1;
                }
                while (iVar5 != 0);
            }
            if (fVar10 != 0.0)
            {
                iVar5 = *(int*)((int)fVar10 + 0x58);
                cVar1 = *(char*)(iVar5 + 0x10f);
                *(char*)(iVar5 + 0x10f) = cVar1 + '\x01';
                *(uint*)(iVar5 + cVar1 * 4 + 0x100) = param_9;
            }
        }
    }
    else
    {
        uVar13 = ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        uVar7 = FUN_80006c00(0);
        if ((uVar7 & 0x100) != 0)
        {
            *(u8*)(puVar12 + 3) = 0;
            uVar13 = FUN_80006ba8(0, 0x100);
        }
        if (((GameObject*)param_9)->unkF8 == 1)
        {
            *(u8*)((int)puVar12 + 5) = 2;
        }
        if ((*(char*)((int)puVar12 + 5) == '\x02') && (((GameObject*)param_9)->unkF8 == 0))
        {
            *(u8*)((int)puVar12 + 5) = 0;
            *(u8*)(puVar12 + 3) = 0;
        }
        if (*(char*)(puVar12 + 3) != '\0')
        {
            ObjMsg_SendToObject(uVar13, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar5, 0x100008,
                                param_9,CONCAT22(puVar12[1], *puVar12), in_r7, in_r8, in_r9, in_r10);
        }
    }
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_801f2b94
 * EN v1.0 Address: 0x801F2B94
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801F37A8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2b94(short* param_1)
{
    int iVar1;
    double dVar2;

    if (*(char*)(*(int*)(param_1 + 0x5c) + 0xc) == '\x02')
    {
        *param_1 = *param_1 + 0x32;
    }
    iVar1 = FUN_80017a98();
    dVar2 = (double)FUN_8001771c((float*)(iVar1 + 0x18), (float*)(param_1 + 0xc));
    if ((double)lbl_803E6A80 <= dVar2)
    {
        FUN_8000680c((int)param_1, 0x40);
    }
    else
    {
        FUN_80006824((uint)param_1,SFXmn_eggylaugh216);
    }
    return;
}


/* Trivial 4b 0-arg blr leaves. */


extern f32 lbl_803E5D78;


extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 timeDelta;


void lightsource_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int dll_1FF_getExtraSize_ret_8(void);
int lightsource_getExtraSize(void) { return 0x1c; }
int lightsource_getObjectTypeId(void) { return 0x1; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5D58;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5E08;
extern void queueGlowRender(void* light);


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

/* if (o->_X == K) return A; else return B; */
int dll_1FF_getObjectTypeId(int* obj);

/* init pattern: short=-1; byte=0; return 0; */


/* fn_X(lbl); lbl = 0; */

/* dll_1FF_init: stash (s8 b[0x18] << 8) into a[0] and -0x8000 into a[1]. */


extern int GameBit_Get(int id);


extern int Obj_GetPlayerObject(void);


extern void ModelLightStruct_free(void* light);

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
extern f32 lbl_803E5D80;

void dll_1FF_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);

/* dll_200_render: when visible != 0 and
 * gMapEventInterface vtable[0x40] applied to obj->_ac returns 4, gate on
 * GameBit_Get(0x2bd); else render directly via objRenderFn_8003b8f4. */


/* dll_200_init: write a function pointer
 * (dll_200_SeqFn) into obj->_bc and prime obj->_b8 (the body block) with
 * fixed bytes, the three float position-quaternion from arg+8/c/10,
 * GameBit_Get(0xd0) latched into b->_24, plus several literal latches. */


extern void GameBit_Set(int slot, int val);


#pragma opt_strength_reduction off

#pragma opt_strength_reduction off


typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

void lightsource_update(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern int ObjHits_GetPriorityHit(int obj, int a, int b, int c);
    extern uint GameBit_Get(int id);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_AddLoopedObjectSound(int obj, int sfx);
    extern void Sfx_RemoveLoopedObjectSound(int obj, int sfx);
    extern void fn_80098B18(int obj, f32 scale, u8 a, u8 b, int c, f32* vec);
    extern EffectInterface** gPartfxInterface;
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


/* segment pragma-stack balance (re-split): */
#pragma opt_strength_reduction reset
#pragma opt_strength_reduction reset

#include "main/dll/LGT/dll_0206_lightsource.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"


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

typedef struct LightColorTable
{
    u8 c[45];
} LightColorTable;

/*
 * --INFO--
 *
 * Function: lightsource_init
 * EN v1.0 Address: 0x801F37CC
 * EN v1.0 Size: 1112b
 */
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

/* Trivial 4b 0-arg blr leaves. */
void lightsource_release(void)
{
}

void lightsource_initialise(void)
{
}

void wmworm_hitDetect(void);

/* 8b "li r3, N; blr" returners. */

