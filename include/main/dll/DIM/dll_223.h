#ifndef MAIN_DLL_DIM_DLL_223_H_
#define MAIN_DLL_DIM_DLL_223_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMbosstonsil.h"

typedef int (*DIMbosstonsilHitReactionCallback)(void* obj, DIMbosstonsilState* state);
typedef int (*DIMbosstonsilUpdateHitReactionCallback)(void* obj, DIMbosstonsilState* state, int unused);

typedef struct DIMbosstonsilStateHandlerTable {
    DIMbosstonsilHitReactionCallback startIdle;
    DIMbosstonsilHitReactionCallback choose;
} DIMbosstonsilStateHandlerTable;

typedef struct DIMbosstonsilSubstateHandlerTable {
    DIMbosstonsilHitReactionCallback enable;
    DIMbosstonsilUpdateHitReactionCallback update;
} DIMbosstonsilSubstateHandlerTable;

int DIMbosstonsil_updateHitReaction(void* obj, DIMbosstonsilState* state, int unused);
int DIMbosstonsil_enableHitReaction(void* obj, DIMbosstonsilState* state);
int DIMbosstonsil_chooseHitReaction(void* obj, DIMbosstonsilState* state);
int DIMbosstonsil_startIdleHitReaction(void* obj, DIMbosstonsilState* state);
void DIMbosstonsil_checkHit(GameObject* obj, DIMbosstonsilState* state);

extern DIMbosstonsilStateHandlerTable lbl_803DDBB0;
extern DIMbosstonsilSubstateHandlerTable lbl_803DDBA8;

STATIC_ASSERT(sizeof(DIMbosstonsilStateHandlerTable) == 8);
STATIC_ASSERT(sizeof(DIMbosstonsilSubstateHandlerTable) == 8);

#endif /* MAIN_DLL_DIM_DLL_223_H_ */
