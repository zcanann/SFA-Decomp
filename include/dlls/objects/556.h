#ifndef DLLS_OBJECTS_556_H_
#define DLLS_OBJECTS_556_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"

/* EN reads establish this prefix through the halfword at 0x20.
 * The complete placement record size is not yet verified. */
typedef struct Dll22CPlacementPrefix {
    ObjPlacement base;
    s8 rotationHighByte;
    u8 unk19;
    s16 parameter1A;    /* converted to float and stored; no state reader in this TU */
    s16 activationMode; /* truncated to a byte; 1 bypasses the activation gamebit */
    s16 gameBit2;
    s16 gameBit;
} Dll22CPlacementPrefix;

/* dll_22C_getExtraSize_ret_16 returns the complete 0x10-byte allocation. */
typedef struct Dll22CState {
    f32 placementValue1A; /* initialized only; motion uses fixed endpoint offsets */
    s16 mode;
    s16 gameBit;
    s16 gameBit2; /* initialized only; no reader in this TU */
    s16 pauseTimer;
    u8 activationMode;
    u8 sfxLatch;
    u8 unk0E[2];
} Dll22CState;

STATIC_ASSERT(offsetof(Dll22CPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(Dll22CPlacementPrefix, rotationHighByte) == 0x18);
STATIC_ASSERT(offsetof(Dll22CPlacementPrefix, parameter1A) == 0x1A);
STATIC_ASSERT(offsetof(Dll22CPlacementPrefix, activationMode) == 0x1C);
STATIC_ASSERT(offsetof(Dll22CPlacementPrefix, gameBit2) == 0x1E);
STATIC_ASSERT(offsetof(Dll22CPlacementPrefix, gameBit) == 0x20);

STATIC_ASSERT(offsetof(Dll22CState, placementValue1A) == 0x00);
STATIC_ASSERT(offsetof(Dll22CState, mode) == 0x04);
STATIC_ASSERT(offsetof(Dll22CState, gameBit) == 0x06);
STATIC_ASSERT(offsetof(Dll22CState, gameBit2) == 0x08);
STATIC_ASSERT(offsetof(Dll22CState, pauseTimer) == 0x0A);
STATIC_ASSERT(offsetof(Dll22CState, activationMode) == 0x0C);
STATIC_ASSERT(offsetof(Dll22CState, sfxLatch) == 0x0D);
STATIC_ASSERT(sizeof(Dll22CState) == 0x10);

extern ObjectDescriptor gDll22CObjDescriptor;

int dll_22C_SeqFn(void);
int dll_22C_getExtraSize_ret_16(void);
int dll_22C_getObjectTypeId(void);
void dll_22C_free(GameObject* obj);
void dll_22C_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_22C_hitDetect_nop(void);
void dll_22C_update(GameObject* obj);
void dll_22C_init(GameObject* obj, Dll22CPlacementPrefix* def);
void dll_22C_release_nop(void);
void dll_22C_initialise_nop(void);

#endif /* DLLS_OBJECTS_556_H_ */
