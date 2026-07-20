#ifndef MAIN_DLL_DLL_00CF_CANNONCLAW_H_
#define MAIN_DLL_DLL_00CF_CANNONCLAW_H_

#include "types.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct CannonClawPlacement
{
    ObjPlacement base;
    u8 pad18[0x28 - 0x18];
    s8 rotXByte;
} CannonClawPlacement;

STATIC_ASSERT(offsetof(CannonClawPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(CannonClawPlacement, rotXByte) == 0x28);

void grimble_initialiseStateHandlerTables(void);
int cannonclaw_getExtraSize(void);
int cannonclaw_getObjectTypeId(void);
void cannonclaw_free(void);
void cannonclaw_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void cannonclaw_hitDetect(void);
void cannonclaw_update(GameObject* obj);
void cannonclaw_init(GameObject* obj, CannonClawPlacement* placement);
void cannonclaw_release(void);
void cannonclaw_initialise(void);

#endif /* MAIN_DLL_DLL_00CF_CANNONCLAW_H_ */
