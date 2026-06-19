#ifndef MAIN_DLL_ALPHAANIM_H_
#define MAIN_DLL_ALPHAANIM_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gDoorLockObjDescriptor;
extern ObjectDescriptor gSeqObjectObjDescriptor;
extern ObjectDescriptor gSeqObj2ObjDescriptor;
extern ObjectDescriptor gIMMultiSeqObjDescriptor;

typedef struct DoorLockPlacement {
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

typedef struct SeqObjectPlacement {
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

typedef struct IMMultiSeqPlacement {
    ObjPlacement base;
    s16 completionGameBits[4];
    s16 activeGameBits[4];
    u8 initialYaw;
    u8 pad29;
    u8 modelBankIndex;
    u8 pad2B;
    s8 triggerIds[4];
    u8 polarityMask;
    u8 pad31[3];
} IMMultiSeqPlacement;

int Lock_DoorLock_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void doorlock_init(short *obj, DoorLockPlacement *config);
void FUN_8017c230(int param_1);
void FUN_8017c254(int param_1,int p1,int p2,int p3,int p4,s8 visible);
void FUN_8017c29c(int param_1);
void FUN_8017c5c0(short *param_1,int param_2);
u32
FUN_8017c608(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,u32 param_10
            ,ObjAnimUpdateState *animUpdate,u32 param_12,int param_13,u32 param_14,u32 param_15,
            u32 param_16);
void seqObject_free(int param_1);
void seqObject_render(int param_1,int p1,int p2,int p3,int p4,s8 visible);
void seqObject_update(int param_1);
void seqObject_init(short *param_1,int param_2);
u32 FUN_8017ca44(int obj, u32 unused, ObjAnimUpdateState *animUpdate);
int seqobject_SeqFn(int *obj, int *anim, ObjAnimUpdateState *animUpdate);
void seqObj2_free(int param_1);
void seqObj2_update(int param_1);
void seqObj2_init(short *param_1,int param_2);
int seqobj2_SeqFn(int *obj, int *anim, ObjAnimUpdateState *animUpdate);

int doorlock_getExtraSize(void);
void doorlock_free(int x);
void doorlock_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void doorlock_update(int obj);

int seqobject_getExtraSize(void);
int seqobject_getObjectTypeId(void);
void fn_8017C294(int *obj);
void seqobject_free(int x);
void seqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void seqobject_update(int *obj);
void seqobject_init(int *obj, SeqObjectPlacement *params);

int seqobj2_getExtraSize(void);
int seqobj2_getObjectTypeId(void);
void seqobj2_free(int x);
void seqobj2_render(void);
void seqobj2_hitDetect(void);
void seqobj2_update(int *obj);
void seqobj2_init(int *obj, SeqObjectPlacement *def);
void SeqObj2_release(void);
void SeqObj2_initialise(void);

int immultiseq_getExtraSize(void);
int immultiseq_getObjectTypeId(void);
void immultiseq_free(int x);
void immultiseq_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void immultiseq_hitDetect(void);
void immultiseq_update(int *obj);
void immultiseq_init(int *obj, IMMultiSeqPlacement *params);
void immultiseq_release(void);
void immultiseq_initialise(void);
int immultiseq_SeqFn(int *obj, int *anim, ObjAnimUpdateState *animUpdate);

#endif /* MAIN_DLL_ALPHAANIM_H_ */
