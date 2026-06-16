#include "main/dll/DF/DFlantern.h"

extern void objRenderFn_8003b8f4(f32);
extern void ModelLightStruct_free(void* light);

extern f32 timeDelta;

#include "main/dll/DF/DFlantern.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objseq.h"

typedef struct SpiritPrizePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 unk18;
    u8 pad1A[0x20 - 0x1A];
} SpiritPrizePlacement;

extern u32 randomGetRange(int min, int max);
extern void objRenderFn_8003b8f4(f32 scale);
extern void objParticleFn_80099d84(int* obj, f32 scale1, int kind, f32 scale2, int light);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern u8 lbl_803DB411;
extern f32 lbl_803E4E9C;
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern void Obj_FreeObject(int obj);
extern int coordsToMapCell(f32 x, f32 z);

typedef struct DfshShrinePlacement
{
    ObjPlacement base;
    s8 initialYaw;
    u8 pad19;
    s16 startDelay;
    u8 pad1C[0x24 - 0x1C];
} DfshShrinePlacement;

STATIC_ASSERT(sizeof(DfshShrinePlacement) == 0x24);
STATIC_ASSERT(offsetof(DfshShrinePlacement, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(DfshShrinePlacement, startDelay) == 0x1A);

extern void* objCreateLight(int* obj, int v);

extern void modelLightStruct_setLightKind(void* light, int v);
extern void modelLightStruct_setDiffuseColor(void* light, int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(void* light, f32 a, f32 b);
extern f32 lbl_803E4E98;
extern f32 lbl_803E4EB0;
extern f32 lbl_803E4EB4;

void SpiritPrize_hitDetect(void)
{
}

void SpiritPrize_release(void)
{
}

void SpiritPrize_initialise(void)
{
}

typedef struct SpiritPrizeState
{
    u8 pad00[0x24];
    f32 spawnScale;
    s32 triggerHandle;
    u8 pad2C[0x57 - 0x2C];
    u8 prizeId;
    u8 pad58[0x6A - 0x58];
    s16 mapParam1A;
    u8 pad6C[0x6E - 0x6C];
    s16 targetObjectId;
    u8 pad70[0x81 - 0x70];
    u8 queuedActions[0x8B - 0x81];
    u8 queuedActionCount;
    u8 pad8C[0x140 - 0x8C];
    void* light;
    u8 useDetachedLight;
    u8 pad145[0x148 - 0x145];
    f32 sfxTimer;
} SpiritPrizeState;

void SpiritPrize_free(int obj)
{
    SpiritPrizeState* state;
    void* light;

    state = ((GameObject*)obj)->extra;
    light = state->light;
    if (light != NULL)
    {
        ModelLightStruct_free(light);
        state->light = NULL;
        state->useDetachedLight = 0;
    }
    (*gObjectTriggerInterface)->freeState((u8*)state);
}

void SpiritPrize_init(int* obj, u8* init)
{
    SpiritPrizeState* state;

    state = ((GameObject*)obj)->extra;
    if (*(u32*)(init + 0x14) == 0x4ca62) return;
    state->mapParam1A = *(s16*)(init + 0x1a);
    state->targetObjectId = -1;
    state->spawnScale = lbl_803E4E98 / (lbl_803E4E98 + (f32)(u32)
    init[0x24]
    )
    ;
    state->triggerHandle = -1;
    if (((GameObject*)obj)->unkF4 == 0)
    {
        if (*(s16*)(init + 0x18) != 1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)state, init);
            ((GameObject*)obj)->unkF4 = *(s16*)(init + 0x18) + 1;
        }
    }
    else
    {
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if (*(s16*)(init + 0x18) != ((GameObject*)obj)->unkF4 - 1)
        {
            (*gObjectTriggerInterface)->freeState((u8*)state);
            if (*(s16*)(init + 0x18) != -1)
            {
                (*gObjectTriggerInterface)->loadAnimData((u8*)state, init);
            }
            ((GameObject*)obj)->unkF4 = *(s16*)(init + 0x18) + 1;
        }
    }
    if (((GameObject*)obj)->anim.seqId != 0x1d9)
    {
        state->useDetachedLight = 1;
    }
    if (state->light == NULL)
    {
        state->light = objCreateLight(state->useDetachedLight != 0 ? NULL : obj, 1);
        if (state->light != NULL)
        {
            modelLightStruct_setLightKind(state->light, 2);
            modelLightStruct_setDiffuseColor(state->light, 0x96, 0x32, 0xff, 0xff);
            modelLightStruct_setDistanceAttenuation(state->light, lbl_803E4EB0, lbl_803E4EB4);
        }
    }
    ((GameObject*)obj)->anim.alpha = 0;
    *(u8*)((char*)obj + 0x37) = 0;
    state->sfxTimer = (f32)(s32)
    randomGetRange(0xb4, 0xf0);
}

void dfsh_objcreator_free(void);

int SpiritPrize_getExtraSize(void) { return 0x14c; }
int SpiritPrize_getObjectTypeId(void) { return 0x8; }
int dfsh_objcreator_getExtraSize(void);

void SpiritPrize_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    SpiritPrizeState* state;
    s32 v;
    state = ((GameObject*)obj)->extra;
    v = visible;
    if (v != 0)
    {
        objRenderFn_8003b8f4(lbl_803E4E98);
        if (state->useDetachedLight != 0)
        {
            objParticleFn_80099d84(obj, lbl_803E4E98, 7, *(f32*)&lbl_803E4E98, (int)state->light);
        }
        else
        {
            objParticleFn_80099d84(obj, lbl_803E4E98, 7, *(f32*)&lbl_803E4E98, 0);
        }
    }
}

void SpiritPrize_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    u8* params;
    SpiritPrizeState* state;
    int childObj;
    int objectCount;
    int objectIndex;
    int* objects;
    int i;

    params = *(u8**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if (params == NULL || ((SpiritPrizePlacement*)params)->unk18 == -1 || ((SpiritPrizePlacement*)params)->unk14 ==
        0x4ca62)
    {
        return;
    }

    for (i = 0; i < state->queuedActionCount; i++)
    {
        switch (state->queuedActions[i])
        {
        case 1:
            state->useDetachedLight = 0;
            break;
        case 2:
            state->useDetachedLight = 1;
            break;
        }
    }

    objectIndex = (*gObjectTriggerInterface)->update((u8*)obj, (f32)(u32)lbl_803DB411);
    if (objectIndex != 0 && ((GameObject*)obj)->seqIndex == -2)
    {
        int matchingObj;
        int prizeId;
        int duplicateCount;

        prizeId = *(s8*)&((SpiritPrizeState*)state)->prizeId;
        matchingObj = 0;
        objects = ObjList_GetObjects(&objectIndex, &objectCount);
        duplicateCount = 0;
        objectIndex = 0;
        while (objectIndex < objectCount)
        {
            childObj = objects[objectIndex];
            if (*(s16*)(childObj + 0xb4) == prizeId)
            {
                matchingObj = childObj;
            }
            if (*(s16*)(childObj + 0xb4) == -2 && ((GameObject*)childObj)->anim.classId == 0x10 &&
                prizeId == (s8)((SpiritPrizeState*)*(int*)&((GameObject*)childObj)->extra)->prizeId)
            {
                duplicateCount++;
            }
            objectIndex++;
        }
        if (duplicateCount <= 1 && (void*)matchingObj != NULL && *(s16*)(matchingObj + 0xb4) != -1)
        {
            *(s16*)(matchingObj + 0xb4) = -1;
            (*gObjectTriggerInterface)->endSequence(prizeId);
        }
        ((GameObject*)obj)->seqIndex = -1;
        Obj_FreeObject(obj);
    }

    state->sfxTimer -= timeDelta;
    if (state->sfxTimer < lbl_803E4E9C)
    {
        int player;

        player = Obj_GetPlayerObject();
        state->sfxTimer = (f32)(s32)
        randomGetRange(0xb4, 0xf0);
        if (((GameObject*)obj)->anim.mapEventSlot == -1 &&
            ((void*)player == NULL || coordsToMapCell(*(f32*)(player + 0xc), *(f32*)(player + 0x14)) == 0xb))
        {
            Sfx_PlayFromObject(obj, 0x4a0);
        }
    }
}
