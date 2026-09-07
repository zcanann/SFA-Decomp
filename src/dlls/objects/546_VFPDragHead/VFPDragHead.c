/* VFPDragHead (DLL 0x0222) */
#include "dlls/object_descriptor.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "game/objects/object_setup.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"

#define VFPDRAGHEAD_RESOURCE_ID     0xA5
#define VFPDRAGHEAD_HIT_VOLUME_SLOT 0xE
#define VFPDRAGHEAD_PARTFX_BREATH   0x390
#define VFPDRAGHEAD_PARTFX_IDLE     0x391


u8 gVfpDragHeadActiveIndex;
s16 gVfpDragHeadSpawnTimer;
void* gVfpDragHeadResource;

typedef struct VfpDragHeadState
{
    s16 gameBitA;
    s16 gameBitB;
    s16 unk_04;
    s16 despawnTimer;
    u8 pad08[3];
    u8 headIndex;
} VfpDragHeadState;

typedef struct VfpDragHeadPlacement
{
    ObjPlacement base;
    s8 rotXByte;
    s8 variant;
    s16 headIndex;
    u8 pad1C[2];
    s16 gameBitA;
    s16 gameBitB;
} VfpDragHeadPlacement;

STATIC_ASSERT(sizeof(VfpDragHeadState) == 0xC);

int VFPDragHead_getExtraSize(void)
{
    return 0xc;
}

int VFPDragHead_getObjectTypeId(void)
{
    return 0x0;
}

void VFPDragHead_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->freeSourceEffects((void*)obj);
    if (gVfpDragHeadResource != NULL)
    {
        Resource_Release(gVfpDragHeadResource);
    }
    gVfpDragHeadResource = NULL;
}

void VFPDragHead_render(void)
{
}

void VFPDragHead_hitDetect(void)
{
}

void VFPDragHead_update(GameObject* obj)
{
    int state = (s8)((VfpDragHeadPlacement*)obj->anim.placement)->variant;
    VfpDragHeadState* self2;

    if (state == 2)
    {
        self2 = obj->extra;
        gVfpDragHeadSpawnTimer -= (s16)timeDelta;
        if (mainGetBit(self2->gameBitB) != 0)
            return;
        if (gVfpDragHeadSpawnTimer > 0xc8)
            return;
        if (self2->headIndex != gVfpDragHeadActiveIndex)
            return;
        if (randomGetRange(0, 2) != 0)
            return;
        (*gPartfxInterface)->spawnObject(obj, VFPDRAGHEAD_PARTFX_IDLE, NULL, 4, -1, NULL);
    }
    else if (obj->anim.romDefNo == 0x3c5)
    {
        self2 = obj->extra;
        self2->despawnTimer -= (s16)timeDelta;
        obj->anim.localPosX =
            obj->anim.velocityX * timeDelta + obj->anim.localPosX;
        obj->anim.localPosY =
            obj->anim.velocityY * timeDelta + obj->anim.localPosY;
        obj->anim.localPosZ =
            obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
        if (self2->despawnTimer > 0)
            return;
        Obj_FreeObject(obj);
    }
    else if (state == 0)
    {
        self2 = obj->extra;
        gVfpDragHeadSpawnTimer -= (s16)timeDelta;
        if (mainGetBit(0x522) != 0)
            return;
        if (gVfpDragHeadSpawnTimer > 0xc8)
            return;
        if (self2->headIndex != gVfpDragHeadActiveIndex)
            return;
        if (randomGetRange(0, 2) != 0)
            return;
        (*gPartfxInterface)->spawnObject(obj, VFPDRAGHEAD_PARTFX_IDLE, NULL, 4, -1, NULL);
    }
    else if (state == 1)
    {
        self2 = obj->extra;
        if (mainGetBit(self2->gameBitA) != 0)
        {
            (*gPartfxInterface)->spawnObject(obj, VFPDRAGHEAD_PARTFX_BREATH, NULL, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, VFPDRAGHEAD_PARTFX_BREATH, NULL, 4, -1, NULL);
            if (randomGetRange(0, 1) != 0)
            {
                (*gPartfxInterface)->spawnObject(obj, VFPDRAGHEAD_PARTFX_IDLE, NULL, 4, -1, NULL);
            }
        }
        if ((s16)ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
        {
            mainSetBits(self2->gameBitA, 1 - mainGetBit(self2->gameBitA));
        }
    }
}

void VFPDragHead_init(GameObject* obj, VfpDragHeadPlacement* data)
{
    VfpDragHeadPlacement* def = data;
    VfpDragHeadState* state = obj->extra;
    if (obj->anim.romDefNo == 0x3c5) {
        state->despawnTimer = 0x78;
        obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase / 2.0f;
        ObjHits_SetHitVolumeSlot(&obj->anim, VFPDRAGHEAD_HIT_VOLUME_SLOT, 1, 0);
    } else {
        obj->anim.rotX = (((s32)def->rotXByte) << 8);
    }
    state->gameBitA = def->gameBitA;
    state->gameBitB = def->gameBitB;
    state->unk_04 = 0x64;
    state->headIndex = def->headIndex;
    if (def->variant == 1)
    {
        obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase / 2.0f;
    }
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    gVfpDragHeadResource = Resource_Acquire(VFPDRAGHEAD_RESOURCE_ID, 1);
}

void VFPDragHead_release(void)
{
}

void VFPDragHead_initialise(void)
{
}


ObjectDescriptor gVFPDragHeadObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFPDragHead_initialise,
    (ObjectDescriptorCallback)VFPDragHead_release,
    0,
    (ObjectDescriptorCallback)VFPDragHead_init,
    (ObjectDescriptorCallback)VFPDragHead_update,
    (ObjectDescriptorCallback)VFPDragHead_hitDetect,
    (ObjectDescriptorCallback)VFPDragHead_render,
    (ObjectDescriptorCallback)VFPDragHead_free,
    (ObjectDescriptorCallback)VFPDragHead_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)VFPDragHead_getExtraSize,
};
