#ifndef MAIN_DLL_DIM_DLL_01C8_DIMBRIDGECOGMAI_H_
#define MAIN_DLL_DIM_DLL_01C8_DIMBRIDGECOGMAI_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gDIMBridgeCogMaiObjDescriptor;

/* The init callback and retained placement pointer use distinct layouts at
 * 0x18: init reads the watched gamebit there, while the update path reads the
 * completion gamebit there and the watched gamebit at 0x1A. */
typedef struct DimbridgecogmaiInitDef
{
    ObjPlacement head;
    s16 watchGameBit;
    u8 pad1A[2];
    u8 rotationAngle;
    u8 flags;
    s8 sequenceGate; /* -1 suppresses sequence dispatch */
    u8 pad1F[0x24 - 0x1F];
} DimbridgecogmaiInitDef;

typedef struct DimbridgecogmaiPlacement
{
    ObjPlacement head;
    s16 doneGameBit;
    s16 watchGameBit;
    u8 rotationAngle;
    u8 flags;
    s8 sequenceGate; /* -1 suppresses sequence dispatch */
    u8 pad1F[0x20 - 0x1F];
} DimbridgecogmaiPlacement;

typedef struct DimbridgecogmaiState
{
    u8 unk0;
} DimbridgecogmaiState;

STATIC_ASSERT(offsetof(DimbridgecogmaiInitDef, watchGameBit) == 0x18);
STATIC_ASSERT(offsetof(DimbridgecogmaiInitDef, rotationAngle) == 0x1C);
STATIC_ASSERT(offsetof(DimbridgecogmaiPlacement, doneGameBit) == 0x18);
STATIC_ASSERT(offsetof(DimbridgecogmaiPlacement, watchGameBit) == 0x1A);
STATIC_ASSERT(offsetof(DimbridgecogmaiPlacement, flags) == 0x1D);
STATIC_ASSERT(offsetof(DimbridgecogmaiPlacement, sequenceGate) == 0x1E);
STATIC_ASSERT(sizeof(DimbridgecogmaiState) == 0x1);

int dimbridgecogmai_getExtraSize(void);
int dimbridgecogmai_getObjectTypeId(void);
void dimbridgecogmai_free(GameObject* obj);
void dimbridgecogmai_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 visible);
void dimbridgecogmai_hitDetect(void);
void dimbridgecogmai_update(GameObject* obj);
void dimbridgecogmai_init(GameObject* obj, DimbridgecogmaiInitDef* def);
int dimbridgecogmai_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void dimbridgecogmai_initialise(void);
void dimbridgecogmai_release(void);

#endif /* MAIN_DLL_DIM_DLL_01C8_DIMBRIDGECOGMAI_H_ */
