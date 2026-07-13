#ifndef MAIN_DLL_ALPHAANIM_H_
#define MAIN_DLL_ALPHAANIM_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gDoorLockObjDescriptor;
extern ObjectDescriptor gSeqObjectObjDescriptor;

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

typedef struct SeqObjectPlacement
{
    ObjPlacement base;
    s16 openGameBit;
    s16 triggerGameBit;
    u8 initialYaw;
    u8 flags;
    s8 triggerId;
    u8 modelBankIndex;
    s16 preemptSequenceId;
    u16 sequenceParam;
    u8 warpMapId;
    u8 pad25[3];
} SeqObjectPlacement;

int Lock_DoorLock_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void Lock_DoorLock_init(short* obj, DoorLockPlacement* config);
void FUN_8017c230(int param_1);
void FUN_8017c254(int param_1, int p1, int p2, int p3, int p4, s8 visible);
void FUN_8017c29c(int param_1);
void FUN_8017c5c0(short* param_1, int param_2);
u32 FUN_8017c608(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5, u64 param_6, u64 param_7,
                 u64 param_8, int param_9, u32 param_10, ObjAnimUpdateState* animUpdate, u32 param_12, int param_13,
                 u32 param_14, u32 param_15, u32 param_16);
void seqObject_free(int param_1);
void seqObject_render(int param_1, int p1, int p2, int p3, int p4, s8 visible);
void seqObject_update(int param_1);
void seqObject_init(short* param_1, int param_2);
u32 FUN_8017ca44(int obj, u32 unused, ObjAnimUpdateState* animUpdate);
int SeqObject_SeqFn(GameObject* obj, int* anim, ObjAnimUpdateState* animUpdate);
void seqObj2_free(int param_1);
void seqObj2_update(int param_1);
void seqObj2_init(short* param_1, int param_2);

int Lock_DoorLock_getExtraSize(void);
void Lock_DoorLock_free(int x);
void Lock_DoorLock_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void Lock_DoorLock_update(GameObject* obj);

int SeqObject_getExtraSize(void);
int SeqObject_getObjectTypeId(void);
void objCallOnloadCallback(GameObject* obj);
void SeqObject_free(GameObject* obj);
void SeqObject_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SeqObject_update(GameObject* obj);
void SeqObject_init(GameObject* obj, SeqObjectPlacement* params);

#endif /* MAIN_DLL_ALPHAANIM_H_ */
