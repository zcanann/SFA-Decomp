#ifndef MAIN_DLL_DIM_DLL_01BE_DIMLAVA_H_
#define MAIN_DLL_DIM_DLL_01BE_DIMLAVA_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"

typedef struct DimLavaPlacement
{
    u8 pad00[0x14];
    s32 linkedObjectId; /* 0x14: consumed and cleared during initialization */
    s8 launchYaw;       /* 0x18: yaw in 1/128 turns */
    u8 pad19;
    s16 verticalSpeed;   /* 0x1A: scaled by 0.1 for the launch velocity */
    s16 horizontalSpeed; /* 0x1C: scaled by 0.1 for the launch velocity */
    u8 pad1E[0x20 - 0x1E];
} DimLavaPlacement;

STATIC_ASSERT(offsetof(DimLavaPlacement, linkedObjectId) == 0x14);
STATIC_ASSERT(offsetof(DimLavaPlacement, launchYaw) == 0x18);
STATIC_ASSERT(offsetof(DimLavaPlacement, verticalSpeed) == 0x1A);
STATIC_ASSERT(offsetof(DimLavaPlacement, horizontalSpeed) == 0x1C);
STATIC_ASSERT(sizeof(DimLavaPlacement) == 0x20);

void lavaball1be_relaunch(GameObject* obj, int verticalSpeed, int horizontalSpeed);
u32 lavaball1be_isInactive(GameObject* obj);
int lavaball1be_getExtraSize(GameObject* obj);
int lavaball1be_getObjectTypeId(GameObject* obj);
void lavaball1be_free(GameObject* obj);
void lavaball1be_render(GameObject* obj, int p2, int p3, int p4, int p5);
void lavaball1be_hitDetect(void);
void lavaball1be_update(GameObject* obj);
void lavaball1be_init(GameObject* obj, DimLavaPlacement* placement);
void lavaball1be_release(void);
void lavaball1be_initialise(void);

extern ObjectDescriptor12 gLavaBall1BEObjDescriptor;

#endif /* MAIN_DLL_DIM_DLL_01BE_DIMLAVA_H_ */
