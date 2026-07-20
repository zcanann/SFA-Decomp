#ifndef MAIN_DLL_DLL_0121_INFOTEXT_H_
#define MAIN_DLL_DLL_0121_INFOTEXT_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct InfoTextSetup
{
    ObjPlacement base;
    u8 rotation;
    u8 hintTextIndex;
    u8 pad1A[2];
} InfoTextSetup;

typedef struct InfoTextState
{
    f32 displayTimer;
} InfoTextState;

STATIC_ASSERT(sizeof(InfoTextSetup) == 0x1c);
STATIC_ASSERT(offsetof(InfoTextSetup, rotation) == 0x18);
STATIC_ASSERT(offsetof(InfoTextSetup, hintTextIndex) == 0x19);
STATIC_ASSERT(sizeof(InfoTextState) == 0x4);

int infotext_getExtraSize(void);
void infotext_update(GameObject* obj);
void infotext_init(GameObject* obj, InfoTextSetup* setup);

#endif /* MAIN_DLL_DLL_0121_INFOTEXT_H_ */
