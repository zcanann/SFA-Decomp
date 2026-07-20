#ifndef MAIN_DLL_SC_DLL_01B8_SCTOTEMPOLE_H_
#define MAIN_DLL_SC_DLL_01B8_SCTOTEMPOLE_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "types.h"

typedef struct SCTotemPolePlacement
{
    ObjPlacement head;
    u8 pad18[2];
    u8 yaw;
} SCTotemPolePlacement;

typedef struct SCTotemPoleState
{
    u16 gameBit;
    u8 currentState;
    u8 previousState;
    f32 animSpeed;
} SCTotemPoleState;

STATIC_ASSERT(offsetof(SCTotemPolePlacement, yaw) == 0x1A);
STATIC_ASSERT(offsetof(SCTotemPoleState, animSpeed) == 0x4);
STATIC_ASSERT(sizeof(SCTotemPoleState) == 0x8);

int sc_totempole_sortCompletionGameBits(u16* recordBits, int newTime);
int sc_totempole_getExtraSize(void);
int sc_totempole_getObjectTypeId(void);
void sc_totempole_free(void);
void sc_totempole_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void sc_totempole_hitDetect(void);
void sc_totempole_update(GameObject* obj);
void sc_totempole_init(GameObject* obj, SCTotemPolePlacement* placement);
void sc_totempole_release(void);
void sc_totempole_initialise(void);

#endif /* MAIN_DLL_SC_DLL_01B8_SCTOTEMPOLE_H_ */
