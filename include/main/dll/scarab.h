#ifndef MAIN_DLL_SCARAB_H_
#define MAIN_DLL_SCARAB_H_

#include "ghidra_import.h"
#include "main/dll/baddie_state.h"
#include "main/object_descriptor.h"

void iceBaddie_update(int param_1,int param_2,int param_3);
void FUN_8015d99c(int param_1,char param_2);
void FUN_8015da00(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_8015daf4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8015db94(int param_1);
void FUN_8015dbd0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_8015dbd4(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10,int param_11);
void FUN_8015dd84(void);
void FUN_8015dda4(void);
void FUN_8015dda8(void);
u32 FUN_8015dffc(int param_1,int param_2);
u32 FUN_8015e060(int param_1,int param_2);
u32
FUN_8015e0d0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,u32 param_9
            ,int param_10);
u32 FUN_8015e260(u32 param_1,int param_2);
u32
FUN_8015e2e0(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_8015e488(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_8015e678(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_8015e88c(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_8015e9f4(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_8015ec98(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
void dll_CE_func0B(int obj, int v);
void FUN_8015f068(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_8015f224(u32 param_1,u32 param_2,int param_3);
void FUN_8015f3c8(int param_1,int param_2,int param_3);
void FUN_8015f534(u32 param_1,u8 param_2);
void FUN_8015f5dc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_8015f6cc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8015f758(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8015f75c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10,int param_11);
void FUN_8015f910(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_8015fab4(u32 param_1,char param_2);
void FUN_8015fae4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8015fb0c(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9);
void iceball_update(u16 *param_1,int param_2);
void FUN_801600a8(u32 param_1);
void FUN_80160190(u32 param_1);
void FUN_8016041c(void);
void FUN_8016043c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80160464(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9);
void FUN_8016075c(int param_1);
u32
FUN_80160798(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10);
u32 FUN_80160984(int param_1,int param_2);
u32 FUN_80160a50(int param_1,int param_2);
u32
FUN_80160aa4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,u32 param_9
            ,int param_10,u32 param_11,u32 param_12,u32 param_13,
            u32 param_14,u32 param_15,u32 param_16);
u32 FUN_80160c5c(int param_1);
u32
FUN_80160cd0(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32 FUN_80160df4(int param_1,int param_2);
void FUN_80160e58(u32 param_1,u32 param_2,int param_3,int param_4);
void FUN_80160fb8(int param_1,int param_2,int param_3);
u32 FUN_80161128(short *param_1,u32 param_2,int param_3);
void FUN_80161130(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
int grimble_stateHandlerB05(int *obj, GroundBaddieState *state);
void FUN_80161220(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80161254(int param_1);
void FUN_80161290(short *param_1);
void FUN_80161578(int param_1,int param_2,int param_3);
u32 FUN_8016157c(int param_1,int param_2);
u32
FUN_801615d4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,int param_9,
            int param_10);
u32 FUN_80161708(short *param_1,int param_2);
bool FUN_80161920(u32 param_1,int param_2);
u32 FUN_80161984(u32 param_1,int param_2);
bool FUN_80161a8c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
u32
FUN_80161c08(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
bool FUN_80161d30(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
u32
FUN_80161ea0(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
int grimble_stateHandlerB04(int *obj, GroundBaddieState *state);
int grimble_stateHandlerB03(int obj, GroundBaddieState *state);
int grimble_stateHandlerB01(int *obj, GroundBaddieState *state);
int grimble_stateHandlerB00(int obj, GroundBaddieState *state);
int grimble_stateHandlerA09(int obj, GroundBaddieState *state);
int grimble_stateHandlerA08(int *obj, GroundBaddieState *state);
int grimble_stateHandlerA07(short *obj, GroundBaddieState *state);
int grimble_stateHandlerA06(int obj, GroundBaddieState *state, f32 speed);
int grimble_stateHandlerA05(short *obj, GroundBaddieState *state);
int grimble_stateHandlerA04(short *obj, GroundBaddieState *state);
int grimble_stateHandlerA03(short *obj, GroundBaddieState *state);
int scarab_updateProximityGate(int *obj, GroundBaddieState *state);

extern ObjectDescriptor11WithPadding gChukChukObjDescriptor;
extern ObjectDescriptor gIceBallObjDescriptor;

#endif /* MAIN_DLL_SCARAB_H_ */
