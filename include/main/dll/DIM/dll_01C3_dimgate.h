#ifndef MAIN_DLL_DIM_DLL_01C3_DIMGATE_H_
#define MAIN_DLL_DIM_DLL_01C3_DIMGATE_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

typedef enum DimgateMode
{
    DIMGATE_MODE_CLOSED = 0,
    DIMGATE_MODE_OPENING = 1,
    DIMGATE_MODE_OPEN = 2,
} DimgateMode;

/* The retail DIMGate placement is fixed at nine words: the common 0x18-byte
 * head followed by this class's 0x0c-byte parameter tail. */
typedef struct DimgateSetup
{
    ObjPlacement base;
    s8 rotX; /* byte angle expanded to anim.rotX by << 8 */
    u8 pad19[0x1e - 0x19];
    s16 gateGameBit;
    u8 pad20[0x24 - 0x20];
} DimgateSetup;

typedef struct DimgateState
{
    s8 mode;
} DimgateState;

STATIC_ASSERT(offsetof(DimgateSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(DimgateSetup, gateGameBit) == 0x1e);
STATIC_ASSERT(sizeof(DimgateSetup) == 0x24);
STATIC_ASSERT(offsetof(DimgateState, mode) == 0x0);
STATIC_ASSERT(sizeof(DimgateState) == 0x1);

int dimgate_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int dimgate_getExtraSize(void);
int dimgate_getObjectTypeId(void);
void dimgate_free(void);
void dimgate_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dimgate_hitDetect(void);
void dimgate_update(GameObject* obj);
void dimgate_init(GameObject* obj, DimgateSetup* unusedSetup);
void dimgate_release(void);
void dimgate_initialise(void);

extern ObjectDescriptor gDIMGateObjDescriptor;

#endif /* MAIN_DLL_DIM_DLL_01C3_DIMGATE_H_ */
