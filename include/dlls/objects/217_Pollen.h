#ifndef DLLS_OBJECTS_217_POLLEN_H_
#define DLLS_OBJECTS_217_POLLEN_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"

typedef struct PollenState {
    s16 phaseX;         /* 0x00 */
    s16 unk02;          /* 0x02 */
    s16 phaseY;         /* 0x04 */
    s16 phaseSpeed;     /* 0x06 */
    f32 settleVelocity; /* 0x08 */
    f32 driftVelocity;  /* 0x0C */
    s16 unk10;          /* 0x10 */
    s16 despawnTimer;   /* 0x12 */
} PollenState;

STATIC_ASSERT(offsetof(PollenState, phaseX) == 0x0);
STATIC_ASSERT(offsetof(PollenState, unk02) == 0x2);
STATIC_ASSERT(offsetof(PollenState, phaseY) == 0x4);
STATIC_ASSERT(offsetof(PollenState, phaseSpeed) == 0x6);
STATIC_ASSERT(offsetof(PollenState, settleVelocity) == 0x8);
STATIC_ASSERT(offsetof(PollenState, driftVelocity) == 0xC);
STATIC_ASSERT(offsetof(PollenState, unk10) == 0x10);
STATIC_ASSERT(offsetof(PollenState, despawnTimer) == 0x12);
STATIC_ASSERT(sizeof(PollenState) == 0x14);

int Pollen_getExtraSize(void);
int Pollen_getObjectTypeId(void);
void Pollen_free(GameObject* obj);
void Pollen_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible);
void Pollen_hitDetect(GameObject* obj);
void Pollen_update(GameObject* obj);
int Pollen_burst(GameObject* obj);
void Pollen_init(GameObject* obj);
void Pollen_release(void);
void Pollen_initialise(void);

extern ObjectDescriptor gPollenObjDescriptor;

#endif /* DLLS_OBJECTS_217_POLLEN_H_ */
