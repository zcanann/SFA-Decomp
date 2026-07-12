#ifndef MAIN_DLL_ARW_DLL_029D_ARWARWINGGU_H
#define MAIN_DLL_ARW_DLL_029D_ARWARWINGGU_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

typedef struct ArwingGuTextureState
{
    u32 textureAnimFlags;
    int textureFrame;
} ArwingGuTextureState;

typedef union ArwingGuState
{
    ArwingGuTextureState texture;
    f32 visibleTimer;
    u8 fadeIn;
} ArwingGuState;

STATIC_ASSERT(sizeof(ArwingGuTextureState) == 8);
STATIC_ASSERT(offsetof(ArwingGuTextureState, textureFrame) == 0x04);
STATIC_ASSERT(sizeof(ArwingGuState) == 8);

extern ObjectDescriptor gARWArwingGuObjDescriptor;
extern f32 lbl_803E7058;
extern f32 lbl_803E705C;
extern f32 lbl_803E7060;

void arwarwinggu_setActiveVisible(GameObject* obj, u8 active, u8 visible);
void arwarwinggu_setTextureFrame(GameObject* obj, int textureFrame);
void arwarwinggu_applyTextureFrame(GameObject* obj);
int ARWArwingGu_getExtraSize(GameObject* obj);
int ARWArwingGu_getObjectTypeId(void);
void ARWArwingGu_free(void);
void ARWArwingGu_render(void);
void ARWArwingGu_hitDetect(void);
void ARWArwingGu_update(GameObject* obj);
void ARWArwingGu_init(GameObject* obj);
void ARWArwingGu_release(void);
void ARWArwingGu_initialise(void);

#endif /* MAIN_DLL_ARW_DLL_029D_ARWARWINGGU_H */
