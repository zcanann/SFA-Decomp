#ifndef MAIN_DLL_DLL_0111_DOORLOCK_H_
#define MAIN_DLL_DLL_0111_DOORLOCK_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct DoorLockPlacement
{
    ObjPlacement base;
    u8 rotXByte;
    u8 rotYByte;
    u8 rotZByte;
    u8 flags;
    s16 lockGameBit;
    u8 pad1E[0x21 - 0x1E];
    u8 modelBankIndex;
    u8 pad22[0x26 - 0x22];
    s16 modeFlags;
} DoorLockPlacement;

typedef struct DoorLockState
{
    u8 unlocked;
} DoorLockState;

extern u32 gDoorLockObjDescriptor[14];

int Lock_DoorLock_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int Lock_DoorLock_getExtraSize(void);
void Lock_DoorLock_free(int obj);
void Lock_DoorLock_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void Lock_DoorLock_update(GameObject* obj);
void Lock_DoorLock_init(short* obj, DoorLockPlacement* config);

#endif /* MAIN_DLL_DLL_0111_DOORLOCK_H_ */
