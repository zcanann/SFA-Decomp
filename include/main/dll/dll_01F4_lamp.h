#ifndef MAIN_DLL_DLL_01F4_LAMP_H_
#define MAIN_DLL_DLL_01F4_LAMP_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct LampPlacement
{
    ObjPlacement base;
    s8 rotXSwing; /* 0x18: rotX byte for the non-static swing seq */
    u8 pad19[0x1A - 0x19];
    u8 rotXStatic; /* 0x1A: rotX byte for the static seq */
    u8 pad1B[0x20 - 0x1B];
} LampPlacement;

typedef struct LampState
{
    u8 active;
} LampState;

STATIC_ASSERT(offsetof(LampPlacement, rotXSwing) == 0x18);
STATIC_ASSERT(offsetof(LampPlacement, rotXStatic) == 0x1a);
STATIC_ASSERT(sizeof(LampPlacement) == 0x20);
STATIC_ASSERT(sizeof(LampState) == 0x1);

int Lamp_getExtraSize(void);
void Lamp_free(GameObject* obj);
void Lamp_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
int Lamp_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void Lamp_update(int obj);
void Lamp_init(GameObject* obj, LampPlacement* placement);

extern ObjectDescriptor gLampObjDescriptor;

#endif /* MAIN_DLL_DLL_01F4_LAMP_H_ */
