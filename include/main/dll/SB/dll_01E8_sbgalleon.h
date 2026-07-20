#ifndef MAIN_DLL_SB_DLL_01E8_SBGALLEON_H_
#define MAIN_DLL_SB_DLL_01E8_SBGALLEON_H_

#include "main/game_object.h"
#include "main/objanim_update.h"

struct SBGalleonState;

GameObject* getSbGalleon(void);
void fn_801E1588(GameObject* obj, struct SBGalleonState* state);
int SB_Galleon_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int SB_Galleon_func0E(int* obj);
u8 SB_Galleon_getDamagePhase(int* obj);
int SB_Galleon_getPhase(int* obj);
s32 SB_Galleon_getStage(int* obj);
int SB_Galleon_onPartDestroyed(GameObject* obj);
int SB_Galleon_getExtraSize(void);
int SB_Galleon_getObjectTypeId(void);
void SB_Galleon_free(GameObject* obj, int leavingMap);
void SB_Galleon_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SB_Galleon_hitDetect(GameObject* obj);
void SB_Galleon_update(GameObject* obj);
void SB_Galleon_init(GameObject* obj);
void SB_Galleon_release(void);
void SB_Galleon_initialise(void);

#endif /* MAIN_DLL_SB_DLL_01E8_SBGALLEON_H_ */
