#ifndef MAIN_DLL_DIM_DIM2PROJROCK_H_
#define MAIN_DLL_DIM_DIM2PROJROCK_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/curve.h"

extern ObjectDescriptor gDIM2IceFloeObjDescriptor;
extern ObjectDescriptor gDIM2IcicleObjDescriptor;
extern ObjectDescriptor12 gDIM2LavaControlObjDescriptor;

void dll_1DA_update(int obj);
void FUN_801b8c60(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b8c88(u32 param_1);
void FUN_801b8d0c(int *param_1);
void FUN_801b932c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b9354(u32 param_1);
void FUN_801b968c(u16 *param_1,int param_2);
void FUN_801b9700(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b9728(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_801b972c(u16 *param_1,int param_2);
void FUN_801b98ec(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b9914(u32 param_1);
void FUN_801b9c2c(u16 *param_1,int param_2);
void FUN_801b9d2c(void);
void FUN_801b9d64(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801b9d8c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_801ba288(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_801ba434(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801ba45c(int param_1);

int dim2icefloe_getExtraSize(void);
int dim2icefloe_getObjectTypeId(void);
void dim2icefloe_free(void);
void dim2icefloe_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2icefloe_hitDetect(void);
void dim2icefloe_update(int obj);
void dim2icefloe_init(int obj, int p);
void dim2icefloe_release(void);
void dim2icefloe_initialise(void);

int dim2icicle_getExtraSize(void);
int dim2icicle_getObjectTypeId(void);
void dim2icicle_free(void);
void dim2icicle_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2icicle_hitDetect(void);
void dim2icicle_update(int obj);
void dim2icicle_init(int obj, s8 *p);
void dim2icicle_release(void);
void dim2icicle_initialise(void);

void dim2lavacontrol_setScale(void* obj);
int dim2lavacontrol_getExtraSize(void);
void dim2lavacontrol_free(void);
void dim2lavacontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2lavacontrol_update(int obj);
void dim2lavacontrol_init(int obj, int param2);
void dll_1DA_init(void* obj);
void dll_1DA_release(void);
void dll_1DA_initialise(void);
int dll_1DB_getExtraSize(void);
int dll_1DB_getObjectTypeId(void);
void dll_1DB_free(void);
void dll_1DB_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_1DB_hitDetect(void);
void dll_1DB_init(void* obj, void* p);
void dll_1DB_release(void);
void dll_1DB_initialise(void);
int dll_1DF_getExtraSize(void);
int dll_1DF_getObjectTypeId(void);
void dll_1DF_free(void);
void dll_1DF_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_1DF_hitDetect(void);
void dll_1DF_update(void* obj);
void dll_1DF_init(void* obj, void* p);
void dll_1DF_release(void);
void dll_1DF_initialise(void);


/* dim2icefloe extra state (dim2icefloe_getExtraSize == 0xBC).
 * Offsets recovered from dim2icefloe_update/init derefs; 0x9C is the
 * followed-object link (null-tested as a pointer, stored as int). */
typedef struct Dim2IceFloeState {
    Curve curve;
    int followedObj;
    int targetId;
    f32 curveStep;
    f32 yawJitter;
    f32 bobRate;
    f32 bobBase;
    s16 bobPhase;
    u8 flags;
    u8 padB7;
    u8 paused;
    u8 finishedFlags;
    u8 padBA[2];
} Dim2IceFloeState;

STATIC_ASSERT(sizeof(Dim2IceFloeState) == 0xBC);
STATIC_ASSERT(offsetof(Dim2IceFloeState, followedObj) == 0x9C);


/* dim2icicle extra state (dim2icicle_getExtraSize == 0xC). */
typedef struct Dim2IcicleState {
    f32 dropY;   /* 0x0: world Y the icicle drops toward / rest height */
    s16 wobbleRotY; /* 0x4: post-impact spin angle, written to anim.rotY and decayed to 0 */
    u8 mode;     /* 0x6 */
    u8 dropTargetFound; /* 0x7: one-shot flag once a drop-target Y is located */
    s16 timer;   /* 0x8 */
    u8 padA[2];
} Dim2IcicleState;

STATIC_ASSERT(sizeof(Dim2IcicleState) == 0xC);

#endif /* MAIN_DLL_DIM_DIM2PROJROCK_H_ */
