#ifndef MAIN_DLL_DLL_01F4_LAMP_H_
#define MAIN_DLL_DLL_01F4_LAMP_H_

#include "main/game_object.h"
#include "global.h"
#include "main/objanim_update.h"

typedef struct LampObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 rotXSwing; /* 0x18: rotX byte for the non-static swing seq */
    u8 pad19[0x1A - 0x19];
    u8 rotXStatic; /* 0x1A: rotX byte for the static seq */
    u8 pad1B[0x20 - 0x1B];
} LampObjectDef;

int Lamp_getExtraSize(void);
void Lamp_free(int* obj);
void Lamp_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
int Lamp_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void Lamp_update(int obj);
void Lamp_init(int* obj, int* def);

#endif /* MAIN_DLL_DLL_01F4_LAMP_H_ */
