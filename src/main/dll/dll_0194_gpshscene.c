/* DLL 0x194 — GP/SH scene controller [801C70F0-801C7724) */
#include "main/screen_transition.h"

/* render-with-objRenderFn_8003b8f4 pattern. */

#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"
extern f32 lbl_803E5058;

void gpsh_scene_free(void)
{
}

void gpsh_scene_hitDetect(void)
{
}

void gpsh_scene_update(void)
{
}

void gpsh_scene_release(void)
{
}

void gpsh_scene_initialise(void)
{
}

void ecsh_cup_hitDetect(void);

int gpsh_scene_getExtraSize(void) { return 0x0; }
int gpsh_scene_getObjectTypeId(void) { return 0x0; }
int ecsh_cup_getExtraSize(void);

void gpsh_scene_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5058);
}

void ecsh_cup_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void gpsh_scene_init(int* obj, int* def)
{
    ((GameObject*)obj)->anim.rotX = (s16)((s32) * (s8*)((char*)def + 0x18) << 8);
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
}

void gpsh_objcreator_init(int* obj, int* def);
