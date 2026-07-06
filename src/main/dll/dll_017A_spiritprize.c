/*
 * spiritprize (DLL 0x17A) - the collectible Krazoa-spirit prize object.
 *
 * Spawns and animates a coloured point light around the prize, runs its
 * trigger/animation sequence each update tick, and periodically plays an
 * ambient sfx near the player. On init it loads the placement's anim data
 * (skipping placements tagged with the SPIRITPRIZE_PLACEMENT_DISABLED
 * sentinel) and creates the light - detached or object-bound depending on
 * the spawn seqId. On update, once its sequence ends (seqIndex == -2) it
 * scans the object list to hand its sequence off to a matching live object
 * and frees itself.
 */
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/engine_shared.h"
#include "main/objlib.h"
#include "main/lightmap.h"
#include "main/audio/sfx_trigger_ids.h"
extern void ModelLightStruct_free(void* light);
extern void objRenderModelAndHitVolumes(int* obj, int p2, int p3, int p4, int p5, f32 scale);
extern void objParticleFn_80099d84(int* obj, f32 scale1, int kind, f32 scale2, int light);

extern void Obj_FreeObject(int obj);

extern void* objCreateLight(int* obj, int v);
extern void modelLightStruct_setLightKind(void* light, int v);
extern void modelLightStruct_setDiffuseColor(void* light, int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(u8* obj, f32 a, f32 b);
extern u8 lbl_803DB411;
extern f32 lbl_803E4E98;
extern f32 lbl_803E4E9C;
extern f32 lbl_803E4EB0;
extern f32 lbl_803E4EB4;

/* placements carrying this id in their mapId are inert and never spawn */
#define SPIRITPRIZE_PLACEMENT_DISABLED 0x4ca62

/* anim.classId of a spirit-prize object */
#define SPIRITPRIZE_CLASS_ID 0x10

typedef struct SpiritPrizePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 mapId;          /* 0x14: placement map id; == DISABLED sentinel means inert */
    s16 triggerOrder;   /* 0x18: trigger sequence index; -1 = none, stored as obj->unkF4 = +1 */
    s16 mapParam1A;     /* 0x1a: copied to state->mapParam1A */
    u8 pad1C[0x24 - 0x1C];
    u8 scaleParam;      /* 0x24: feeds spawnScale = base / (base + scaleParam) */
    u8 pad25[0x40 - 0x25];
} SpiritPrizePlacement;

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

void SpiritPrize_hitDetect(void)
{
}

void SpiritPrize_release(void)
{
}

void SpiritPrize_initialise(void)
{
}

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
    SpiritPrizePlacement* placement;
    SpiritPrizeState* state;
    int triggerId;

    placement = (SpiritPrizePlacement*)init;
    state = ((GameObject*)obj)->extra;
    if (placement->mapId == SPIRITPRIZE_PLACEMENT_DISABLED) return;
    state->mapParam1A = placement->mapParam1A;
    state->targetObjectId = -1;
    state->spawnScale = lbl_803E4E98 / (lbl_803E4E98 + (f32)(u32)placement->scaleParam);
    state->triggerHandle = -1;
    triggerId = ((GameObject*)obj)->unkF4;
    if (triggerId == 0)
    {
        if (placement->triggerOrder != 1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)state, init);
            ((GameObject*)obj)->unkF4 = placement->triggerOrder + 1;
            goto afterTrigger;
        }
    }
    if (triggerId != 0)
    {
        if (placement->triggerOrder != triggerId - 1)
        {
            (*gObjectTriggerInterface)->freeState((u8*)state);
            if (placement->triggerOrder != -1)
            {
                (*gObjectTriggerInterface)->loadAnimData((u8*)state, init);
            }
            ((GameObject*)obj)->unkF4 = placement->triggerOrder + 1;
        }
    }
afterTrigger:;
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
    ((GameObject*)obj)->anim.pad37[0] = 0;
    state->sfxTimer = (f32)(s32)randomGetRange(0xb4, 0xf0);
}

int SpiritPrize_getExtraSize(void) { return sizeof(SpiritPrizeState); }
int SpiritPrize_getObjectTypeId(void) { return 0x8; }

void SpiritPrize_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    SpiritPrizeState* state;
    s32 isVisible;

    state = ((GameObject*)obj)->extra;
    isVisible = visible;
    if (isVisible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E4E98);
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
    if (params == NULL)
    {
        return;
    }
    if (((SpiritPrizePlacement*)params)->triggerOrder == -1)
    {
        return;
    }
    if (((SpiritPrizePlacement*)params)->mapId == SPIRITPRIZE_PLACEMENT_DISABLED)
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

        prizeId = *(s8*)&state->prizeId;
        matchingObj = 0;
        objects = ObjList_GetObjects(&objectIndex, &objectCount);
        duplicateCount = objectIndex = 0;
        while (objectIndex < objectCount)
        {
            childObj = objects[objectIndex];
            if (((GameObject*)childObj)->seqIndex == prizeId)
            {
                matchingObj = childObj;
            }
            if (((GameObject*)childObj)->seqIndex == -2 && ((GameObject*)childObj)->anim.classId == SPIRITPRIZE_CLASS_ID &&
                prizeId == (s8)((SpiritPrizeState*)*(int*)&((GameObject*)childObj)->extra)->prizeId)
            {
                duplicateCount++;
            }
            objectIndex++;
        }
        if (duplicateCount <= 1 && (void*)matchingObj != NULL && ((GameObject*)matchingObj)->seqIndex != -1)
        {
            ((GameObject*)matchingObj)->seqIndex = -1;
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
            ((void*)player == NULL || coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ) == 0xb))
        {
            Sfx_PlayFromObject(obj, SFXTRIG_pda);
        }
    }
}
