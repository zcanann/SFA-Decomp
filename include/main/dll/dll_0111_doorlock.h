#ifndef MAIN_DLL_DLL_0111_DOORLOCK_H_
#define MAIN_DLL_DLL_0111_DOORLOCK_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

typedef struct DoorLockPlacement
{
    ObjPlacement base;
    u8 rotXByte;
    u8 rotYByte;
    u8 rotZByte;
    u8 flags;               /* 0x1B: placement behavior bits */
    s16 lockGameBit;        /* 0x1C */
    s16 prereqGameBit0;     /* 0x1E */
    s8 unlockSequenceId;    /* 0x20 */
    u8 modelBankIndex;      /* 0x21 */
    s16 prereqGameBit1;     /* 0x22 */
    s16 queuedSequenceId;   /* 0x24 */
    s16 modeFlags;          /* 0x26 */
} DoorLockPlacement;

STATIC_ASSERT(offsetof(DoorLockPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(DoorLockPlacement, lockGameBit) == 0x1C);
STATIC_ASSERT(offsetof(DoorLockPlacement, unlockSequenceId) == 0x20);
STATIC_ASSERT(offsetof(DoorLockPlacement, queuedSequenceId) == 0x24);
STATIC_ASSERT(sizeof(DoorLockPlacement) == 0x28);

typedef struct DoorLockState
{
    u8 unlocked;
} DoorLockState;

STATIC_ASSERT(sizeof(DoorLockState) == 0x1);

extern ObjectDescriptor gDoorLockObjDescriptor;

int Lock_DoorLock_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int Lock_DoorLock_getExtraSize(void);
void Lock_DoorLock_free(GameObject* obj);
void Lock_DoorLock_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void Lock_DoorLock_update(GameObject* obj);
void Lock_DoorLock_init(GameObject* obj, DoorLockPlacement* placement);

#endif /* MAIN_DLL_DLL_0111_DOORLOCK_H_ */
