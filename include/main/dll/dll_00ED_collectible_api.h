#ifndef MAIN_DLL_DLL_00ED_COLLECTIBLE_API_H_
#define MAIN_DLL_DLL_00ED_COLLECTIBLE_API_H_

#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor17 gCollectibleObjDescriptor;

void collectible_applyPickup(int* obj);
void collectible_free(GameObject* obj);
int collectible_getExtraSize(void);
int collectible_getHitRegionId(int* obj);
int collectible_getIsHidden(int* obj);
int collectible_getObjectTypeId(void);
u8 collectible_getVisibilityBitClear(int* obj);
void collectible_hitDetect(void);
void collectible_init(GameObject* obj, int setup);
void collectible_initialise(void);
void collectible_release(void);
void collectible_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
int collectible_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void collectible_setDisabled(int* obj, int disabled);
void collectible_setPosition(int* obj, f32 x, f32 y, f32 z);
void collectible_setVisibilityBitClear(int* obj, u32 clear);
void collectible_startBounceMotion(int* obj, f32 x, f32 y, f32 z);
void collectible_update(int obj);
void collectible_updateIdleMotion(GameObject* obj);

#endif /* MAIN_DLL_DLL_00ED_COLLECTIBLE_API_H_ */
