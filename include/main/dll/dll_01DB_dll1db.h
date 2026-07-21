#ifndef MAIN_DLL_DLL_01DB_DLL1DB_H_
#define MAIN_DLL_DLL_01DB_DLL1DB_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct Dim2CrusherPlacement
{
    ObjPlacement base;
    s8 rotX;
    u8 pad19[5];
    s16 boardedGameBit;
    s16 triggerGameBit;
    u8 pad22[6];
} Dim2CrusherPlacement;

typedef struct Dim2CrusherState
{
    f32 velocity;
    u8 motionState;
    u8 boardedFlag;
    u8 contactLostFlag;
    u8 pad07;
} Dim2CrusherState;

STATIC_ASSERT(offsetof(Dim2CrusherPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(Dim2CrusherPlacement, boardedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(Dim2CrusherPlacement, triggerGameBit) == 0x20);
STATIC_ASSERT(sizeof(Dim2CrusherPlacement) == 0x28);
STATIC_ASSERT(sizeof(Dim2CrusherState) == 0x8);

int dll_1DB_getExtraSize(void);
int dll_1DB_getObjectTypeId(void);
void dll_1DB_free(void);
void dll_1DB_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_1DB_hitDetect(void);
void dll_1DB_update(GameObject* obj);
void dll_1DB_init(GameObject* obj, Dim2CrusherPlacement* placement);
void dll_1DB_release(void);
void dll_1DB_initialise(void);

extern ObjectDescriptor dll_1DB;

#endif /* MAIN_DLL_DLL_01DB_DLL1DB_H_ */
