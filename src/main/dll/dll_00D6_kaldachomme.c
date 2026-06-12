#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/wallanimator.h"


extern undefined4 FUN_80006824();
extern undefined4 FUN_800175cc();
extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008112c();
extern void queueGlowRender(void* light);

extern EffectInterface** gPartfxInterface;
extern f64 DOUBLE_803e3d80;
extern f32 lbl_803E3D78;
extern f32 timeDelta;
extern f32 lbl_803E30D0;
extern f32 lbl_803E30D4;
extern f32 lbl_803E30D8;
extern f32 lbl_803E30E0;

extern int ObjList_FindObjectById(int id);

typedef struct KaldaChompMeState
{
    f32 progress;
    f32 step;
    f32 targetProgress;
    u8 moveId;
    u8 pad0D[3];
} KaldaChompMeState;

/*
 * --INFO--
 *
 * Function: kaldachompme_setLinkedMouthMode
 * EN v1.0 Address: 0x80169360
 * EN v1.0 Size: 556b
 */
void kaldachompme_setLinkedMouthMode(u8* obj, u8 mode)
{
    KaldaChompMeState* state;
    int obj2;

    if (obj == NULL)
    {
        return;
    }
    switch (*(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14))
    {
    case 0x43d14:
        obj2 = ObjList_FindObjectById(0x4b3b5);
        break;
    case 0x41be9:
        obj2 = ObjList_FindObjectById(0x4b3f9);
        break;
    case 0x41cc4:
        obj2 = ObjList_FindObjectById(0x4b402);
        break;
    case 0x41cc5:
        obj2 = ObjList_FindObjectById(0x4b403);
        break;
    case 0x41cc6:
        obj2 = ObjList_FindObjectById(0x4b404);
        break;
    case 0x41cc7:
        obj2 = ObjList_FindObjectById(0x4b40b);
        break;
    case 0x41cc8:
        obj2 = ObjList_FindObjectById(0x4b40c);
        break;
    case 0x41cc9:
        obj2 = ObjList_FindObjectById(0x4b40f);
        break;
    case 0x41cd2:
        obj2 = ObjList_FindObjectById(0x4b410);
        break;
    case 0x41ccc:
        obj2 = ObjList_FindObjectById(0x4b411);
        break;
    case 0x41cd5:
        obj2 = ObjList_FindObjectById(0x4b414);
        break;
    case 0x41cd6:
        obj2 = ObjList_FindObjectById(0x4b415);
        break;
    case 0x41cd9:
        obj2 = ObjList_FindObjectById(0x4b453);
        break;
    default:
        return;
    }
    state = *(KaldaChompMeState**)(obj2 + 0xb8);
    if (state != NULL)
    {
        switch (mode)
        {
        case 1:
            state->targetProgress = lbl_803E30D0;
            state->progress = lbl_803E30D4;
            state->step = lbl_803E30D8;
            state->moveId = 0;
            break;
        case 2:
            state->targetProgress = lbl_803E30D0;
            state->progress = lbl_803E30D4;
            state->step = lbl_803E30D8;
            state->moveId = 1;
            break;
        }
    }
}

int kaldachompme_getExtraSize(void)
{
    return 0x10;
}

int kaldachompme_getObjectTypeId(void)
{
    return 0;
}

void kaldachompme_free(void)
{
}

void kaldachompme_render(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4,
                         undefined4 param_5, s8 renderFlag)
{
    extern void objRenderFn_8003b8f4(double scale); /* #57 */
    s32 v = renderFlag;
    if (v != 0)
    {
        objRenderFn_8003b8f4(lbl_803E30D0);
    }
}

void kaldachompme_hitDetect(void)
{
}

void kaldachompme_update(int obj)
{
    float target;
    float current;
    float step;
    KaldaChompMeState* extra;

    extra = ((GameObject*)obj)->extra;
    current = extra->progress;
    target = extra->targetProgress;
    if (current != target)
    {
        step = extra->step;
        if (step > lbl_803E30D4)
        {
            if (current < target)
            {
                extra->progress = current + step * timeDelta;
            }
            else
            {
                extra->progress = target;
            }
        }
        else
        {
            if (current > target)
            {
                extra->progress = current + step * timeDelta;
            }
            else
            {
                extra->progress = target;
            }
        }
    }
    ObjAnim_SetCurrentMove(obj, extra->moveId, extra->progress, 0);
}

void kaldachompme_init(int obj, int params)
{
    ((GameObject*)obj)->anim.rotZ = (s16)(*(u8*)(params + 0x18) << 8);
    ((GameObject*)obj)->anim.rotY = (s16)(*(u8*)(params + 0x19) << 8);
    ((GameObject*)obj)->anim.rotX = (s16)(*(u8*)(params + 0x1a) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E30D4, 0);
}

void kaldachompme_release(void)
{
}

void kaldachompme_initialise(void)
{
}

ObjectDescriptor gKaldaChompMeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)kaldachompme_initialise,
    (ObjectDescriptorCallback)kaldachompme_release,
    0,
    (ObjectDescriptorCallback)kaldachompme_init,
    (ObjectDescriptorCallback)kaldachompme_update,
    (ObjectDescriptorCallback)kaldachompme_hitDetect,
    (ObjectDescriptorCallback)kaldachompme_render,
    (ObjectDescriptorCallback)kaldachompme_free,
    (ObjectDescriptorCallback)kaldachompme_getObjectTypeId,
    kaldachompme_getExtraSize,
};

/*
 * --INFO--
 *
 * Function: FUN_801695e8
 * EN v1.0 Address: 0x801695E8
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8016980C
 * EN v1.1 Size: 576b
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
 * Function: FUN_8016980c
 * EN v1.0 Address: 0x8016980C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80169A4C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016980c(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_80169a44
 * EN v1.0 Address: 0x80169A44
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x80169B80
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80169a44(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    uint uVar1;
    int* piVar2;
    int local_18[2];
    undefined4 local_10;
    uint uStack_c;

    piVar2 = ((GameObject*)param_9)->extra;
    ((GameObject*)param_9)->anim.alpha = 0;
    *(undefined4*)(param_9 + 0xf4) = 0xdc;
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->flags &= ~1;
    if (*piVar2 != 0)
    {
        FUN_800175cc((double)lbl_803E3D78, *piVar2, '\0');
    }
    if (((GameObject*)param_9)->anim.seqId == 0x869)
    {
        uVar1 = randomGetRange(0, 1);
        uStack_c = randomGetRange(0x32, 0x3c);
        FUN_8008112c((double)(float)((double)CONCAT44(0x43300000, uStack_c) - DOUBLE_803e3d80), param_2,
                     param_3, param_4, param_5, param_6, param_7, param_8, param_9, 1, 1, 0, uVar1 & 0xff, 0, 1, 0);
    }
    else
    {
        for (local_18[0] = 0; local_18[0] < 0x19; local_18[0] = local_18[0] + 1)
        {
            (*gPartfxInterface)->spawnObject((void*)param_9, 0x715, NULL, 1, -1, local_18);
        }
        FUN_80006824(param_9, SFXsc_attack03);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_80169c04
 * EN v1.0 Address: 0x80169C04
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80169CC8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/* Trivial 4b 0-arg blr leaves. */
void kaldachompspit_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int kaldachompspit_getExtraSize(void);
int kaldachompspit_getObjectTypeId(void);

extern void ModelLightStruct_free(void* p);

void kaldachompspit_free(int* obj);

void kaldachompspit_render(void* obj, int p2, int p3, int p4, int p5, s8 visible);

extern void modelLightStruct_setEnabled(int light, int onoff, f32 intensity);
extern void spawnExplosion(int obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Sfx_SetObjectChannelVolume(int obj, int channel, u8 vol, f32 scale);
extern int Obj_FreeObject(int obj);
extern int getAngle(f32 a, f32 b);
extern f32 sqrtf(f32 x);
extern void fn_80098B18(int obj, f32 scale, int a, int b, int c, int d);
extern f32 lbl_803E30F0;
extern f32 lbl_803E30F4;
extern f32 lbl_803E30F8;
extern f32 lbl_803E30FC;
void kaldachompspit_burst(int obj);

/*
 * --INFO--
 *
 * Function: kaldachompspit_update
 * EN v1.0 Address: 0x801698E8
 * EN v1.0 Size: 988b
 */
void kaldachompspit_update(int obj);

/*
 * --INFO--
 *
 * Function: kaldachompspit_burst
 * EN v1.0 Address: 0x801696D4
 * EN v1.0 Size: 312b
 */
void kaldachompspit_burst(int obj);

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset

/* === moved from main/dll/xyzanimator.c [80169CC4-80169EF4) (TU re-split, docs/boundary_audit.md) === */
#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/xyzanimator.h"
#include "main/effect_interfaces.h"
#include "main/objhits_types.h"
#include "main/game_object.h"





/* pollenfragment extra block (head; timers at 0x20/0x24 stay raw addr args). */




/*
 * --INFO--
 *
 * Function: kaldachompspit_render
 * EN v1.0 Address: 0x8016984C
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x80169CF8
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: kaldachompspit_init
 * EN v1.0 Address: 0x80169CC4
 * EN v1.0 Size: 552b
 * EN v1.1 Address: 0x8016A170
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void* objCreateLight(int obj, int kind);
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int alpha, f32 radius);
extern void modelLightStruct_setDiffuseTargetColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void lightSetField4D(int light, int v);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);
extern void modelLightStruct_startColorFade(int light, int a, int b);
extern f32 lbl_803E3108;
extern f32 lbl_803E310C;

void kaldachompspit_init(int obj);


#pragma dont_inline on
void fn_8016A660(int obj);
#pragma dont_inline reset


/*
 * --INFO--
 *
 * Function: pollenfragment_init
 * EN v1.0 Address: 0x8016B0A4
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x8016ACA4
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_8016b228
 * EN v1.0 Address: 0x8016B228
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8016AE70
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
void kaldachompspit_release(void);

void kaldachompspit_initialise(void);









void mikabomb_hitDetect(void);








/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */




ObjectDescriptor gKaldaChompSpitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)kaldachompspit_initialise,
    (ObjectDescriptorCallback)kaldachompspit_release,
    0,
    (ObjectDescriptorCallback)kaldachompspit_init,
    (ObjectDescriptorCallback)kaldachompspit_update,
    (ObjectDescriptorCallback)kaldachompspit_hitDetect,
    (ObjectDescriptorCallback)kaldachompspit_render,
    (ObjectDescriptorCallback)kaldachompspit_free,
    (ObjectDescriptorCallback)kaldachompspit_getObjectTypeId,
    kaldachompspit_getExtraSize,
};

ObjectDescriptor gPinPonSpikeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pinponspike_initialise,
    (ObjectDescriptorCallback)pinponspike_release,
    0,
    (ObjectDescriptorCallback)pinponspike_init,
    (ObjectDescriptorCallback)pinponspike_update,
    (ObjectDescriptorCallback)pinponspike_hitDetect,
    (ObjectDescriptorCallback)pinponspike_render,
    (ObjectDescriptorCallback)pinponspike_free,
    (ObjectDescriptorCallback)pinponspike_getObjectTypeId,
    pinponspike_getExtraSize,
};

ObjectDescriptor gPollenObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollen_initialise,
    (ObjectDescriptorCallback)pollen_release,
    0,
    (ObjectDescriptorCallback)pollen_init,
    (ObjectDescriptorCallback)pollen_update,
    (ObjectDescriptorCallback)pollen_hitDetect,
    (ObjectDescriptorCallback)pollen_render,
    (ObjectDescriptorCallback)pollen_free,
    (ObjectDescriptorCallback)pollen_getObjectTypeId,
    pollen_getExtraSize,
};

PollenFragmentConfig lbl_80320538 = {
    0x0000,
    0x049F,
    0x00B9,
    0x04BA,
    0x04BA,
    -1,
    0.2f,
    0x0000,
    0xC000,
};

PollenFragmentConfig lbl_8032054C = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x7000,
};

PollenFragmentConfig lbl_80320560 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x2000,
};

PollenFragmentConfig lbl_80320574 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    -1,
    0.2f,
    0x0000,
    0x2000,
};

PollenFragmentConfig lbl_80320588 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x3000,
};

PollenFragmentConfig* lbl_8032059C[] = {
    &lbl_80320538,
    &lbl_8032054C,
    &lbl_80320560,
    &lbl_80320574,
    &lbl_80320588,
};



ObjectDescriptor gPollenFragmentObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollenfragment_initialise,
    (ObjectDescriptorCallback)pollenfragment_release,
    0,
    (ObjectDescriptorCallback)pollenfragment_init,
    (ObjectDescriptorCallback)pollenfragment_update,
    (ObjectDescriptorCallback)pollenfragment_hitDetect,
    (ObjectDescriptorCallback)pollenfragment_render,
    (ObjectDescriptorCallback)pollenfragment_free,
    (ObjectDescriptorCallback)pollenfragment_getObjectTypeId,
    pollenfragment_getExtraSize,
};



/* ==== v1.0 recovered functions (drift additions) ==== */



extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);





