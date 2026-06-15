#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/xyzanimator.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800175cc();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008112c();

extern f64 DOUBLE_803e3d80;
extern f32 lbl_803E3D78;
extern f32 timeDelta;
extern f32 lbl_803E30D0;
extern f32 lbl_803E30D4;
extern f32 lbl_803E30D8;

extern int ObjList_FindObjectById(int id);

typedef struct KaldaChompMeState
{
    f32 progress;
    f32 step;
    f32 targetProgress;
    u8 moveId;
    u8 pad0D[3];
} KaldaChompMeState;

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

#pragma scheduling on
#pragma peephole on
void FUN_8016980c(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

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

int kaldachompspit_getExtraSize(void);
int kaldachompspit_getObjectTypeId(void);

void kaldachompspit_free(int* obj);

void kaldachompspit_update(int obj);

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
