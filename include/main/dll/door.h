#ifndef MAIN_DLL_DOOR_H_
#define MAIN_DLL_DOOR_H_

#include "ghidra_import.h"

typedef struct DfpTargetBlockObject DfpTargetBlockObject;
typedef struct DfpTargetBlockCollisionPoints DfpTargetBlockCollisionPoints;

void dfptargetblock_resolveCollisionPoints(DfpTargetBlockObject *obj,
                                           DfpTargetBlockCollisionPoints *collisionPoints);
int dfptargetblock_getExtraSize(void);
int dfptargetblock_func08(void);
void dfptargetblock_free(void);
void dfptargetblock_render(int obj);

#endif /* MAIN_DLL_DOOR_H_ */
