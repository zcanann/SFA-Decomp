/* DLL 0x194 - GP/SH scene controller [801C70F0-801C7724) */
#include "main/screen_transition.h"
#include "main/dll/dll_0194_gpshscene.h"

#include "main/game_object.h"
#include "main/object_render_legacy.h"
#include "main/object_descriptor.h"
__declspec(section ".sdata2") f32 lbl_803E5058 = 1.0f;

typedef struct GpshScenePlacement
{
    u8 pad0[0x18];
    s8 rotXByte;
} GpshScenePlacement;

int gpsh_scene_getExtraSize(void) { return 0x0; }
int gpsh_scene_getObjectTypeId(void) { return 0x0; }

void gpsh_scene_free(void)
{
}

void gpsh_scene_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5058);
}

void gpsh_scene_hitDetect(void)
{
}

void gpsh_scene_update(void)
{
}

void gpsh_scene_init(int* obj, int* def)
{
    GpshScenePlacement* place = (GpshScenePlacement*)def;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)place->rotXByte << 8);
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
}

void gpsh_scene_release(void)
{
}

void gpsh_scene_initialise(void)
{
}

ObjectDescriptor gGPSH_SceneObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)gpsh_scene_initialise, (ObjectDescriptorCallback)gpsh_scene_release, 0,
    (ObjectDescriptorCallback)gpsh_scene_init, (ObjectDescriptorCallback)gpsh_scene_update,
    (ObjectDescriptorCallback)gpsh_scene_hitDetect, (ObjectDescriptorCallback)gpsh_scene_render,
    (ObjectDescriptorCallback)gpsh_scene_free, (ObjectDescriptorCallback)gpsh_scene_getObjectTypeId,
    gpsh_scene_getExtraSize,
};
