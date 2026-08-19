/* VFP_Block1 (DLL 0x021E) */
#include "dlls/object_descriptor.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/expgfx_interface.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/dll/VF/dll_021E_vfpblock1.h"


typedef struct VfpBlock1State
{
    s16 gameBitId;
} VfpBlock1State;

struct VfpBlock1Placement
{
    ObjPlacement base;
    s8 rotXByte;
    u8 pad19[5];
    s16 gameBitId;
};

int VFP_Block1_getExtraSize(void)
{
    return 0x2;
}

int VFP_Block1_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_Block1_free(int obj)
{
    (*gExpgfxInterface)->freeSource2(obj);
}

void VFP_Block1_render(void)
{
}

void VFP_Block1_hitDetect(void)
{
}

void VFP_Block1_update(GameObject* obj) {
    GameObject* player = Obj_GetPlayerObject();
    f32 dist = Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX);

    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) != 0) {
        if (dist < 90.0f) {
            Sfx_PlayFromObject(obj, SFXTRIG_mv_mushdizzylp12);
        }
    } else {
        if (dist >= 90.0f) {
            Sfx_StopObjectChannel(obj, 0x40);
        }
    }
}

void VFP_Block1_init(GameObject* obj, VfpBlock1Placement* data)
{
    VfpBlock1Placement* def = data;
    VfpBlock1State* state = obj->extra;
    obj->anim.rotX = (((s32)def->rotXByte) << 8);
    state->gameBitId = def->gameBitId;
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void VFP_Block1_release(void)
{
}

void VFP_Block1_initialise(void)
{
}

ObjectDescriptor gVFP_Block1ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_Block1_initialise,
    (ObjectDescriptorCallback)VFP_Block1_release,
    0,
    (ObjectDescriptorCallback)VFP_Block1_init,
    (ObjectDescriptorCallback)VFP_Block1_update,
    (ObjectDescriptorCallback)VFP_Block1_hitDetect,
    (ObjectDescriptorCallback)VFP_Block1_render,
    (ObjectDescriptorCallback)VFP_Block1_free,
    (ObjectDescriptorCallback)VFP_Block1_getObjectTypeId,
    VFP_Block1_getExtraSize,
};
