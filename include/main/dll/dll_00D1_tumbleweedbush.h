#ifndef MAIN_DLL_LADDERS_H_
#define MAIN_DLL_LADDERS_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

/* Bush variant anim.seqIds and the sibling tumbleweed seqId each one spawns.
 * The sibling ids match backpack.h's TUMBLEWEED_TYPE_1/3/4 (0x39d/0x4ba/0x4c1). */
#define TUMBLEWEEDBUSH_SEQ_A 0x28d /* -> sibling 0x39d (sun-gated) */
#define TUMBLEWEEDBUSH_SEQ_B 0x3fd /* -> sibling 0x3fb */
#define TUMBLEWEEDBUSH_SEQ_C 0x4b9 /* -> sibling 0x4ba */
#define TUMBLEWEEDBUSH_SEQ_D 0x4be /* -> sibling 0x4c1 */

#define TUMBLEWEEDBUSH_SIBLING_A 0x39d
#define TUMBLEWEEDBUSH_SIBLING_B 0x3fb
#define TUMBLEWEEDBUSH_SIBLING_C 0x4ba
#define TUMBLEWEEDBUSH_SIBLING_D 0x4c1

void cannonclaw_update(u8* obj);
void FUN_80163388(int param_1,u32 param_2,int param_3);
void FUN_8016338c(void);
void FUN_801633ac(void);
void FUN_801633b0(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801633e4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_80163544(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_801638bc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801638e4(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_801638e8(u32 param_1,u32 param_2,int param_3);
int FUN_80163ac8(float *param_1);
void FUN_80163b8c(int param_1);
extern ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor;


/* extern-cleanup: defining-file public prototypes */
s8 fn_801631C8(int* obj);

#endif /* MAIN_DLL_LADDERS_H_ */
