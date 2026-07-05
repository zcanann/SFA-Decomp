/*
 * ShipBattle (DLL 0x01F5) - the chain object of the Lylat-cruise
 * ship-battle set piece (objectTypeId 0xB). It builds the multi-segment
 * chain from the placement def, optionally spawns a point light on the
 * fire sequence (0x171), and is the segment that drives the shared trigger
 * sequence (gObjectTriggerInterface) each frame. When the sequence
 * reaches its pending state (seqIndex == -2) the chain scans the object
 * list for its sequence-group peers and ends the group once it is the
 * last one standing, then frees itself.
 *
 * The cloud-ball, fireball and kyte-cage projectile state blocks of the
 * wider set piece are owned by sibling DLLs; their layouts are pulled in
 * and size-asserted here only so the shared object def lines up.
 */
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/VF/vf_shared.h"
#include "main/objlib.h"

#define MODEL_LIGHT_KIND_POINT 2

typedef struct ShipBattleObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 segmentIndex; /* chain index of this segment (-1 = head) */
    s16 unk1A;
    u8 pad1C[0x24 - 0x1C];
    u8 dampingDivisor; /* feeds state->unk24 damping factor */
    u8 pad25[0x28 - 0x25];
} ShipBattleObjectDef;

STATIC_ASSERT(sizeof(SBCloudBallState) == 0x24);
STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);
STATIC_ASSERT(sizeof(SBKyteCageState) == 0x8);
STATIC_ASSERT(sizeof(ShipBattleState) == 0x140);

#define SHIPBATTLE_OBJECT_TYPE_ID 0xb
#define SHIPBATTLE_FIRE_SEQ_ID 0x171
#define SEQINDEX_PENDING -2
#define CLASSID_SEQUENCE_OBJECT 0x10

extern void** gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy

extern f32 lbl_803E5958;
extern f32 lbl_803E595C;
extern f32 lbl_803E5960;
extern f32 lbl_803E5970;
extern f32 lbl_803E5974;
extern u8 lbl_803DB411;
extern f32 lbl_803DDC50[2];
extern void ModelLightStruct_free(int* p);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern void modelLightStruct_setDiffuseColor(int light, int p, int r, int g, int p2);
extern void modelLightStruct_setLightKind(int light, int v);
extern int objCreateLight(int* obj, int mode);
extern void objfx_spawnFlaggedTrailBurst(int* obj, f32 f, int a, int b, int c, void* d);


void ShipBattle_hitDetect(void)
{
}

void ShipBattle_release(void)
{
}

void ShipBattle_initialise(void)
{
}

int ShipBattle_getExtraSize(void) { return 0x140; }
int ShipBattle_getObjectTypeId(void) { return SHIPBATTLE_OBJECT_TYPE_ID; }

void ShipBattle_free(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    int light;
    (*gObjectTriggerInterface)->freeState((u8*)state);
    ((void(*)(int*, int, int, int, int))((void**)*gTitleMenuControlInterface)[2])(obj, 0xffff, 0, 0, 0);
    light = ((GameObject*)obj)->unkF8;
    if (light != 0)
    {
        ModelLightStruct_free((int*)light);
    }
}

void ShipBattle_init(int obj, int def)
{
    ShipBattleState* state;
    int light;
    int chainIndex;

    state = ((GameObject*)obj)->extra;
    state->unk6A = ((ShipBattleObjectDef*)def)->unk1A;
    state->unk6E = -1;
    state->unk24 =
        lbl_803E595C / (lbl_803E595C + (f32)((ShipBattleObjectDef*)def)->dampingDivisor);
    state->unk28 = -1;

    chainIndex = ((GameObject*)obj)->unkF4;
    if (chainIndex == 0)
    {
        if (((ShipBattleObjectDef*)def)->segmentIndex != 1)
        {
            (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)def);
            ((GameObject*)obj)->unkF4 = ((ShipBattleObjectDef*)def)->segmentIndex + 1;
            goto light_setup;
        }
    }

    if (chainIndex != 0)
    {
        if (((ShipBattleObjectDef*)def)->segmentIndex != chainIndex - 1)
        {
            (*gObjectTriggerInterface)->freeState((u8*)state);
            if (((ShipBattleObjectDef*)def)->segmentIndex != -1)
            {
                (*gObjectTriggerInterface)->loadAnimData((u8*)state, (u8*)def);
            }
            ((GameObject*)obj)->unkF4 = ((ShipBattleObjectDef*)def)->segmentIndex + 1;
        }
    }

light_setup:
    if (((GameObject*)obj)->anim.seqId == SHIPBATTLE_FIRE_SEQ_ID)
    {
        light = objCreateLight((int*)obj, 1);
        if ((u32)light != 0)
        {
            modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setDiffuseColor(light, 200, 60, 0, 0);
            modelLightStruct_setDistanceAttenuation(light, lbl_803E5970, lbl_803E5974);
        }
        ((GameObject*)obj)->unkF8 = light;
    }

    lbl_803DDC50[0] = lbl_803E5958;
    *(u8*)&lbl_803DDC50[1] = 0;
}

void ShipBattle_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E595C);
    if (((GameObject*)obj)->anim.seqId == SHIPBATTLE_FIRE_SEQ_ID)
    {
        objfx_spawnFlaggedTrailBurst(obj, lbl_803E5960, 4, 389, 5, NULL);
    }
}

void ShipBattle_update(int obj)
{
    int groupId;
    int* objects;
    int i;
    int objectCount;
    int current;
    int linkedObject;
    int groupId2;
    int sameGroupCount;

    if (((GameObject*)obj)->anim.placementData == NULL)
    {
        return;
    }
    if (((ShipBattleObjectDef*)((GameObject*)obj)->anim.placementData)->segmentIndex == -1)
    {
        return;
    }

    i = (*gObjectTriggerInterface)->update((u8*)obj, lbl_803DB411);
    if (i == 0)
    {
        return;
    }
    if (((GameObject*)obj)->seqIndex != SEQINDEX_PENDING)
    {
        return;
    }

    groupId = *(s8*)&((ObjSeqState*)((GameObject*)obj)->extra)->slot;
    linkedObject = 0;
    objects = ObjList_GetObjects(&i, &objectCount);
    sameGroupCount = 0;
    i = 0;
    groupId2 = groupId;
    groupId2 |= groupId;
    while (i < objectCount)
    {
        current = objects[i];
        if (((GameObject*)current)->seqIndex == groupId)
        {
            linkedObject = current;
        }
        if (((GameObject*)current)->seqIndex == SEQINDEX_PENDING && ((GameObject*)current)->anim.classId == CLASSID_SEQUENCE_OBJECT &&
            groupId2 == *(s8*)&((ObjSeqState*)((GameObject*)current)->extra)->slot)
        {
            sameGroupCount++;
        }
        i++;
    }

    if (sameGroupCount <= 1 && (void*)linkedObject != NULL && ((GameObject*)linkedObject)->seqIndex != -1)
    {
        ((GameObject*)linkedObject)->seqIndex = -1;
        (*gObjectTriggerInterface)->endSequence(groupId2);
    }
    ((GameObject*)obj)->seqIndex = -1;
    Obj_FreeObject(obj);
}
