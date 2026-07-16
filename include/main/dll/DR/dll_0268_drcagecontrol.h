#ifndef MAIN_DLL_DR_DLL_0268_DRCAGECONTROL_H_
#define MAIN_DLL_DR_DLL_0268_DRCAGECONTROL_H_

#include "main/game_object.h"
#include "global.h"

typedef struct CageControlPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 armGameBit;   /* 0x1E: game bit that pre-opens the cage */
    s16 watchGameBit; /* 0x20: drives the pickup sfx + completion */
    u8 pad22[0x28 - 0x22];
} CageControlPlacement;

STATIC_ASSERT(offsetof(CageControlPlacement, armGameBit) == 0x1E);
STATIC_ASSERT(offsetof(CageControlPlacement, watchGameBit) == 0x20);
STATIC_ASSERT(sizeof(CageControlPlacement) == 0x28);


int DR_CageControl_SeqFn(GameObject* obj);
int DR_CageControl_getExtraSize(void);
int DR_CageControl_getObjectTypeId(void);
void DR_CageControl_free(void);
void DR_CageControl_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void DR_CageControl_hitDetect(void);
void DR_CageControl_update(GameObject* obj);
void DR_CageControl_init(GameObject* obj, char* arg);
void DR_CageControl_release(void);
void DR_CageControl_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0268_DRCAGECONTROL_H_ */
