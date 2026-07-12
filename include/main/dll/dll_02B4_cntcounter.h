#ifndef MAIN_DLL_DLL_02B4_CNTCOUNTER_H
#define MAIN_DLL_DLL_02B4_CNTCOUNTER_H

#include "main/dll/cntcounter_state.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct CntCounterSetup
{
    ObjPlacement base;
    u8 pad18;
    u8 displayHud;
    s16 initialCount;
    s16 pad1C;
    s16 doneGameBit;
    s16 decrementGameBit;
} CntCounterSetup;

STATIC_ASSERT(offsetof(CntCounterSetup, displayHud) == 0x19);
STATIC_ASSERT(offsetof(CntCounterSetup, initialCount) == 0x1A);
STATIC_ASSERT(offsetof(CntCounterSetup, doneGameBit) == 0x1E);
STATIC_ASSERT(offsetof(CntCounterSetup, decrementGameBit) == 0x20);
STATIC_ASSERT(sizeof(CntCounterSetup) == 0x24);

int CntCounter_getExtraSize(void);
int CntCounter_getObjectTypeId(void);
void CntCounter_free(GameObject* obj);
void CntCounter_hitDetect(void);
void CntCounter_render(void);
void CntCounter_init(GameObject* obj);
void CntCounter_update(GameObject* obj);
void CntCounter_release(void);
void CntCounter_initialise(void);

#endif
