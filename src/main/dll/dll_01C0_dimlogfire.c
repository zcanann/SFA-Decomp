/* DLL 0x01C0 (dimlogfire) — DIM logfire object [0x801B0670-0x801B0DD4). */
#include "main/audio/sfx_ids.h"
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/dll/lavaball1bfstate_struct.h"
#include "main/dll/imspacethrusterstate_struct.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/dll/imanimspacecraftstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/dll/DIM/dimlogfire.h"
#include "main/objseq.h"





/* imanimspacecraft_getExtraSize == 0x4. */


STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

/* imspacethruster_getExtraSize == 0xc. */


STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

/* link_levcontrol_getExtraSize == 0x10. */


STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

/* lavaball1be extra (getExtraSize 0x14 for the non-0x1fa variant). */


STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

/* lavaball1bf_getExtraSize == 0x1c (launcher). */


STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

static inline int* DIMcannon_GetActiveModel(void* obj);

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();

extern EffectInterface** gPartfxInterface;

extern void imicepillar_free(void);
extern int imicepillar_getObjectTypeId(void);
extern int imicepillar_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: imicepillar_render
 * EN v1.0 Address: 0x801AE100
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801AE134
 * EN v1.1 Size: 44b
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
 * Function: FUN_801ae184
 * EN v1.0 Address: 0x801AE184
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801AE160
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801ae9e4
 * EN v1.0 Address: 0x801AE9E4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801AE9BC
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
 * Function: FUN_801aea18
 * EN v1.0 Address: 0x801AEA18
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AE9EC
 * EN v1.1 Size: 76b
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
 * Function: FUN_801aea40
 * EN v1.0 Address: 0x801AEA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AEA38
 * EN v1.1 Size: 148b
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
 * Function: FUN_801aea44
 * EN v1.0 Address: 0x801AEA44
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801AEACC
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
 * Function: FUN_801b0190
 * EN v1.0 Address: 0x801B0190
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801AFE04
 * EN v1.1 Size: 96b
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
 * Function: FUN_801b01e8
 * EN v1.0 Address: 0x801B01E8
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x801AFE64
 * EN v1.1 Size: 200b
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
void imicepillar_hitDetect(void);

void imicepillar_update(void);

void imicepillar_init(void);

void imicepillar_release(void);

void imicepillar_initialise(void);

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};





















/* 8b "li r3, N; blr" returners. */
int dimlogfire_getExtraSize(void) { return 0x24; }
int dimlogfire_getObjectTypeId(void) { return 0x1; }

/* Pattern wrappers. */
extern u32 lbl_803DDB48;

/* Init: clear obj->_F4 and record obj globally in lbl_803DDB48. */

/* If obj->_F4 == 0, set it to 1; else early-return. */

/* Free: call vtable[6] on obj through global dll-services pointer. */



/* setScale (test): is bit (1 << idx) set in obj->_b8->_2? Returns 1/0. */

/* lavaball1bf "consume" hook: only clear pending flag if both gates set. */

/* lavaball1bf "request" hook: set pending if gated, return success. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);






/* if (o->_X == K) return A; else return B;  pattern. */


/* chained byte mask. */

int fn_801B0784(int obj, int delta)
{
    s8* inner = ((GameObject*)obj)->extra;
    inner[0x1c] = (s8)(inner[0x1c] - delta);
    return inner[0x1c] <= 0;
}

extern void Music_Trigger(int id, int p2);










extern f32 timeDelta;










extern void ModelLightStruct_free(void* light);






void dimlogfire_free(int* obj, int mode)
{
    extern void Obj_FreeObject(void* o); /* #57 */
    DimLogFireState* inner = ((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if ((void*)inner->subObj != NULL && mode == 0)
    {
        Obj_FreeObject((int*)inner->subObj);
    }
    ObjGroup_RemoveObject(obj, 0x31);
    if ((void*)inner->light != NULL)
    {
        ModelLightStruct_free((void*)inner->light);
    }
}

extern void Sfx_StopObjectChannel(int* obj, int channel);

int dimlogfire_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int Sfx_PlayFromObject(int* obj, int sfxId); /* #57 */
    DimLogFireState* state = ((GameObject*)obj)->extra;
    if (state->mode == 1)
    {
        Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
    }
    else
    {
        Sfx_StopObjectChannel(obj, 64);
    }
    switch (animUpdate->triggerCommand)
    {
    case 1:
        state->smokeToggle = (u8)(state->smokeToggle ^ 1);
        break;
    case 2:
        GameBit_Set(46, 1);
        break;
    case 3:
        state->mode = 4;
        break;
    }
    if (state->smokeToggle != 0)
    {
        (*gPartfxInterface)->spawnObject(obj, 215, NULL, 0, -1, NULL);
        Sfx_StopObjectChannel(obj, 5);
    }
    else
    {
        Sfx_StopObjectChannel(obj, 1);
    }
    animUpdate->triggerCommand = 0;
    return 0;
}

extern void queueGlowRender(int* obj);
extern f32 lbl_803E4820;

void dimlogfire_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    DimLogFireState* state;
    int* subobj;
    if ((s32)visible != 0)
    {
        state = ((GameObject*)obj)->extra;
        subobj = (int*)state->subObj;
        if (subobj != NULL)
        {
            int* q = (int*)((ObjAnimComponent*)subobj)->banks[((ObjAnimComponent*)subobj)->bankIndex];
            *(u16*)((char*)q + 0x18) = (u16)(*(u16*)((char*)q + 0x18) & ~0x8);
            *(u8*)((char*)(int*)state->subObj + 0x37) = *(u8*)((char*)obj + 0x37);
            ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(
                (int*)state->subObj, p2, p3, p4, p5, lbl_803E4820);
        }
        ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E4820);
        if (*(void**)&state->light != NULL)
        {
            if (*(u8*)((char*)*(void**)&state->light + 0x2f8) != 0)
            {
                if (*(u8*)((char*)*(void**)&state->light + 0x4c) != 0)
                {
                    queueGlowRender(*(int**)&state->light);
                }
            }
        }
    }
}

extern int modelLightStruct_getActiveState(int* p);













/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
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
#pragma peephole reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMlavasmash.h"
#include "main/dll/DIM/dimlogfire.h"
#include "main/objanim_internal.h"

typedef struct DimlogfirePlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
    u8 pad20[0x68 - 0x20];
    void* unk68;
    u8 pad6C[0x70 - 0x6C];
} DimlogfirePlacement;


typedef struct DimlogfireObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 strengthInit;
    s16 unk1E;
} DimlogfireObjectDef;




extern undefined4 ObjHits_SetHitVolumeSlot();
extern void fn_80098B18(int obj, f32 scale, int type, int param_4, int param_5, int param_6);
extern undefined4 ObjGroup_AddObject();
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setEnabled(int light, int mode, f32 value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_startColorFade(int light, int param_2, int param_3);
extern void modelLightStruct_setDiffuseTargetColor(int light, int r, int g, int b, int a);

extern f32 lbl_803E4824;
extern f32 lbl_803E4828;
extern f32 lbl_803E482C;
extern f32 lbl_803E4830;
extern f32 lbl_803E4834;
extern f32 lbl_803E4838;
extern f32 lbl_803E483C;

/*
 * --INFO--
 *
 * Function: dimlogfire_update
 * EN v1.0 Address: 0x801B0924
 * EN v1.0 Size: 708b
 * EN v1.1 Address: 0x801B0B58
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimlogfire_update(int obj)
{
    extern int getTrickyObject(void); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfxId); /* #57 */
    int a;
    int b;
    int rand;
    s16 alpha;
    uint light;
    int tricky;
    DimLogFireState* state;
    struct
    {
        f32 x, y, z;
    } vec;

    state = ((GameObject*)obj)->extra;
    tricky = *(int*)&((GameObject*)obj)->anim.placementData;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    switch (state->mode)
    {
    case 1:
        if (*(int**)&state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 1, lbl_803E4824);
        }
        Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
        state->flickerTimerA = state->flickerTimerA - timeDelta;
        if (state->flickerTimerA <= lbl_803E4828)
        {
            a = 7;
            state->flickerTimerA = state->flickerTimerA + lbl_803E482C;
        }
        else
        {
            a = 0;
        }
        state->flickerTimerB = state->flickerTimerB - timeDelta;
        if (state->flickerTimerB <= lbl_803E4828)
        {
            b = 1;
            state->flickerTimerB = state->flickerTimerB + lbl_803E4820;
        }
        else
        {
            b = 0;
        }
        vec.x = lbl_803E4828;
        vec.y = lbl_803E482C;
        vec.z = lbl_803E4828;
        fn_80098B18(obj, ((GameObject*)obj)->anim.rootMotionScale, 2, a, b, (int)&vec);
        ObjHits_SetHitVolumeSlot(obj, 0x1f, 1, 0);
        break;
    case 2:
        if (*(int**)&state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 0, lbl_803E4824);
        }
        if (state->strengthInit <= 0)
        {
            ObjHits_DisableObject(obj);
            state->mode = 1;
            state->dousedLatch = 1;
            GameBit_Set(((DimlogfirePlacement*)tricky)->unk1E, 1);
        }
        tricky = getTrickyObject();
        if ((uint)tricky != 0)
        {
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
            {
                (*(void (**)(int, int, int, int))(**(int**)&((DimlogfirePlacement*)tricky)->unk68 + 0x28))(
                    tricky, obj, 1, 4);
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
        }
        ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
        break;
    case 4:
        break;
    default:
        if (state->unk18 == 0)
        {
            state->mode = 1;
            state->dousedLatch = 1;
        }
        else
        {
            state->mode = 2;
        }
        break;
    }
    if (*(s8*)&state->dousedLatch != 0)
    {
        state->dousedLatch = 0;
    }
    light = state->light;
    if (light != 0 && *(u8*)(light + 0x2f8) != 0 && *(u8*)(light + 0x4c) != 0)
    {
        rand = randomGetRange(-0x19, 0x19);
        light = state->light;
        alpha = *(u8*)(light + 0x2f9) + (*(s8*)(light + 0x2fa) + rand);
        if (alpha < 0)
        {
            alpha = 0;
            *(u8*)(light + 0x2fa) = 0;
        }
        else if (alpha > 0xff)
        {
            alpha = 0xff;
            *(u8*)(light + 0x2fa) = 0;
        }
        *(u8*)(state->light + 0x2f9) = alpha;
    }
}

/*
 * --INFO--
 *
 * Function: FUN_801b09dc
 * EN v1.0 Address: 0x801B09DC
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801B0C24
 * EN v1.1 Size: 336b
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
 * Function: dimlogfire_init
 * EN v1.0 Address: 0x801B0BE8
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x801B0DFC
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dimlogfire_init(int obj, int def)
{
    extern void modelLightStruct_setGlowProjectionRadius(int light, f32 radius); /* #57 */
    extern void modelLightStruct_setupGlow(int light, int param_2, int r, int g, int b, int a, f32 radius); /* #57 */
    extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far); /* #57 */
    extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a); /* #57 */
    extern void modelLightStruct_setLightKind(int light, int value); /* #57 */
    extern int objCreateLight(int obj, int param_2); /* #57 */
    int radius;
    DimLogFireState* state;

    ((GameObject*)obj)->animEventCallback = (void*)dimlogfire_SeqFn;
    ObjGroup_AddObject(obj, 0x31);
    state = ((GameObject*)obj)->extra;
    state->unk20 = 0;
    state->unk18 = ((DimlogfireObjectDef*)def)->unk1A;
    state->strengthInit = (s8)((DimlogfireObjectDef*)def)->strengthInit;
    *(u8*)&state->strength = *(u8*)&state->strengthInit;
    if (GameBit_Get(((DimlogfireObjectDef*)def)->unk1E) != 0)
    {
        state->mode = 1;
        state->dousedLatch = 1;
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
    state->flickerTimerA = lbl_803E482C;
    state->flickerTimerB = lbl_803E4820;
    if (*(int**)&state->light == NULL)
    {
        state->light = objCreateLight(obj, 1);
    }
    if (*(int**)&state->light != NULL)
    {
        modelLightStruct_setLightKind(state->light, 2);
        modelLightStruct_setDiffuseColor(state->light, 0xff, 0x7f, 0, 0xff);
        modelLightStruct_setSpecularColor(state->light, 0xff, 0x7f, 0, 0xff);
        radius = (int)(lbl_803E4830 * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setDistanceAttenuation(state->light, (f32)radius, lbl_803E4834 + (f32)radius);
        modelLightStruct_setEnabled(state->light, 1, lbl_803E4828);
        modelLightStruct_setPosition(state->light, lbl_803E4828, lbl_803E4838, *(f32*)&lbl_803E4828);
        modelLightStruct_startColorFade(state->light, 1, 3);
        modelLightStruct_setDiffuseTargetColor(state->light, 0xff, 0x5c, 0, 0xff);
        modelLightStruct_setupGlow(state->light, 0, 0xff, 0x7f, 0, 0x87,
                                   lbl_803E483C * ((GameObject*)obj)->anim.rootMotionScale);
        modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E4834);
    }
}

/*
 * --INFO--
 *
 * Function: dimsnowball_getExtraSize
 * EN v1.0 Address: 0x801B0DD4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801B0F50
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimsnowball_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: dimsnowball_getObjectTypeId
 * EN v1.0 Address: 0x801B0DDC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801B0F58
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dimsnowball_free
 * EN v1.0 Address: 0x801B0DE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B0F60
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* render-with-objRenderFn_8003b8f4 pattern. */




/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset

/* === moved from main/dll/DIM/dimsnowball_init.c [801B1354-801B13E8) (TU re-split, docs/boundary_audit.md) === */








