#ifndef MAIN_DLL_TRICKY_H_
#define MAIN_DLL_TRICKY_H_

#include "ghidra_import.h"

void gameUiLoadResources(void);
void FUN_8011d9b4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8011daf8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8011dc74(int param_1,u8 param_2,u32 param_3,char param_4);
u32 FUN_8011df18(int param_1,int *param_2,int param_3);
void FUN_8011e454(double param_1,double param_2,double param_3,double param_4,int param_5,
                 int param_6,int param_7,int param_8);
void FUN_8011e458(u64 param_1,double param_2,u32 param_3,u32 param_4,
                 u8 param_5,int param_6,int param_7,int param_8,int param_9);
void FUN_8011e45c(u64 param_1,double param_2,u32 param_3,u32 param_4,
                 u8 param_5,u32 param_6,int param_7,int param_8,u32 param_9);
void FUN_8011e460(double param_1,double param_2,int param_3,int param_4,u8 param_5,
                 u32 param_6,u8 param_7);
void FUN_8011e464(double param_1,double param_2,double param_3,double param_4,u16 param_5,
                 u16 param_6,u16 param_7);
void FUN_8011e7ac(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u8 FUN_8011e7b0(void);
void FUN_8011e7bc(u8 param_1);
void FUN_8011e7c8(u8 param_1);
void FUN_8011e800(u8 param_1);
void FUN_8011e80c(void);
short FUN_8011e824(u16 *param_1);
void FUN_8011e844(u8 param_1);
void FUN_8011e85c(u16 param_1);
void FUN_8011e868(u16 param_1);
void FUN_8011e880(void);
void FUN_8011eb10(u16 param_1);
void FUN_8011eb1c(u8 param_1,u8 param_2,u16 param_3);
void FUN_8011eb38(u8 param_1);
void FUN_8011eb44(void);
void FUN_8011ebb8(void);
void FUN_8011f040(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_8011f044(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_8011f048(u32 param_1,u32 param_2,u32 param_3,u32 param_4,
                 u32 param_5,u32 param_6,u32 param_7,u32 param_8);
void FUN_8011f04c(u32 param_1,u32 *param_2);
void FUN_8011f210(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_8011f2c4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_8011f438(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);


/* extern-cleanup: defining-file public prototypes */
void pauseMenuTextDrawFn(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);
void hudDrawAirMeter(void);
void fearTestMeterDraw(void);
void pauseMenuMapFn_8011de20(void *this, int a, s16 b, int c);
void fn_8011EF50(u16 a, u16 b, u16 c, f32 f1, f32 f2, f32 f3, f32 f4);

#endif /* MAIN_DLL_TRICKY_H_ */
