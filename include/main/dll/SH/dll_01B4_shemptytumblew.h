#ifndef MAIN_DLL_SH_DLL_01B4_SHEMPTYTUMBLEW_H_
#define MAIN_DLL_SH_DLL_01B4_SHEMPTYTUMBLEW_H_

#include "main/obj_placement.h"
#include "main/game_object.h"

typedef struct ShEmptyTumblewPlacement
{
    ObjPlacement head;
    u8 rotZByte;
    u8 rotYByte;
    u8 rotXByte;
    u8 pad1b;
    f32 scale;
} ShEmptyTumblewPlacement;

STATIC_ASSERT(offsetof(ShEmptyTumblewPlacement, rotZByte) == 0x18);
STATIC_ASSERT(offsetof(ShEmptyTumblewPlacement, scale) == 0x1c);

void SH_EmptyTumbleW_update(GameObject* obj);
void SH_EmptyTumbleW_init(s16* obj, ShEmptyTumblewPlacement* def);

#endif /* MAIN_DLL_SH_DLL_01B4_SHEMPTYTUMBLEW_H_ */
