/*
 * NW_geyser (DLL 0x1A0) - the erupting geyser of SnowHorn Wastes (map
 * 'nwastes', 0x0A).
 *
 * The geyser plays a pair of looped object sounds and continuously runs
 * its trigger sequence. Once its disable game bit is set, it hides, drops
 * its sounds and collision, and reports completion to the area's level
 * controller. Its animation-event callback scrolls the geyser texture.
 */
#include "dlls/objects/416_NW_geyser.h"

#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/objhits.h"

#define NW_GEYSER_DISABLE_GAMEBIT    0xA
#define NW_GEYSER_COMPLETION_GAMEBIT 0x398

#define NW_GEYSER_LOOP_SFX_A 0x372
#define NW_GEYSER_LOOP_SFX_B 0x373

#define NW_GEYSER_TEXTURE_SCROLL_PERIOD        0x4E80
#define NW_GEYSER_OBJECT_GROUP                 0x1F
#define NW_GEYSER_SEQUENCE_FLAG_TEXTURE_SCROLL 0x40

typedef struct NwGeyserTextureScrollParams {
    f32 unitsPerSecond;
    f32 unknown04;
} NwGeyserTextureScrollParams;

STATIC_ASSERT(sizeof(NwGeyserTextureScrollParams) == 0x08);
STATIC_ASSERT(offsetof(NwGeyserTextureScrollParams, unitsPerSecond) == 0x00);
STATIC_ASSERT(offsetof(NwGeyserTextureScrollParams, unknown04) == 0x04);

static const NwGeyserTextureScrollParams sNwGeyserTextureScrollParams = {512.0f, 0.0f};

int nwGeyser_processAnimEvents(GameObject* obj, int unusedArg, ObjSeqState* animUpdate) {
    ObjTextureRuntimeSlot* texture;

    (void)unusedArg;
    if (mainGetBit(NW_GEYSER_DISABLE_GAMEBIT) != 0) {
        animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
    }
    texture = objFindTexture(obj, 0, 0);
    objFindTexture(obj, 1, 0);
    texture->offsetT = texture->offsetT + (s32)(sNwGeyserTextureScrollParams.unitsPerSecond * timeDelta);
    if (texture->offsetT > NW_GEYSER_TEXTURE_SCROLL_PERIOD) {
        texture->offsetT -= NW_GEYSER_TEXTURE_SCROLL_PERIOD;
    }
    animUpdate->flags = (s16)(animUpdate->savedFlags & ~NW_GEYSER_SEQUENCE_FLAG_TEXTURE_SCROLL);
    animUpdate->movementState = 0;
    return 0;
}

void nwGeyser_free(GameObject* obj) {
    (*gMapEventInterface)->setObjGroupStatus(obj->anim.mapEventSlot, NW_GEYSER_OBJECT_GROUP, 0);
}

void nwGeyser_update(GameObject* obj) {
    if (mainGetBit(NW_GEYSER_DISABLE_GAMEBIT) != 0) {
        obj->anim.flags = OBJANIM_FLAG_HIDDEN;
        obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_UPDATE_DISABLED);
        Sfx_RemoveLoopedObjectSound(obj, NW_GEYSER_LOOP_SFX_A);
        Sfx_RemoveLoopedObjectSound(obj, NW_GEYSER_LOOP_SFX_B);
        ObjHits_DisableObject(obj);
        mainSetBits(NW_GEYSER_COMPLETION_GAMEBIT, 1);
    } else {
        Sfx_AddLoopedObjectSound(obj, NW_GEYSER_LOOP_SFX_A);
        Sfx_AddLoopedObjectSound(obj, NW_GEYSER_LOOP_SFX_B);
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        ObjHits_EnableObject(obj);
    }
}

void nwGeyser_init(GameObject* obj) {
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED));
    obj->animEventCallback = nwGeyser_processAnimEvents;
}

ObjectDescriptor gNWGeyserObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)nwGeyser_init,
    (ObjectDescriptorCallback)nwGeyser_update,
    0,
    0,
    (ObjectDescriptorCallback)nwGeyser_free,
    0,
    0,
};
