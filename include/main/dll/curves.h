#ifndef MAIN_DLL_CURVES_H_
#define MAIN_DLL_CURVES_H_

#include "ghidra_import.h"

undefined4
FUN_800e1da8(double param_1,double param_2,double param_3,uint *param_4,float *param_5,
            float *param_6,float *param_7);
undefined4 FUN_800e21c0(double param_1,undefined8 param_2,double param_3,int param_4,int param_5);
void FUN_800e2278(undefined8 param_1,double param_2,double param_3);
int FUN_800e2498(double param_1,double param_2,double param_3,int param_4);
void FUN_800e260c(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4);
void FUN_800e2b94(undefined4 param_1,undefined4 param_2,int param_3,int *param_4);
int RomCurve_getRandomLinkedOfTypes(int param_1,int param_2,int param_3,int *param_4);
double curves_distXZ(double param_1,double param_2,uint param_3);
double RomCurve_distanceToObject(int param_1,uint param_2);
void curves_find(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 *param_6,undefined4 *param_7,undefined4 *param_8);
undefined4 RomCurve_getById(uint param_1,int *param_2);
void FUN_800e3a00(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5);
int FUN_800e45b4(int param_1);
void FUN_800e4854(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4);
void RomCurve_getAdjacentWindow(int param_1,int *param_2);
int RomCurve_getNearestAdjacentLink(double param_1,double param_2,double param_3,int param_4,
                                    int param_5);
double RomCurve_distanceToSegment(double param_1,double param_2,double param_3,float *param_4);
int RomCurve_getRandomBlockedLink(int param_1,int param_2);
int RomCurve_getRandomUnblockedLink(int param_1,int param_2);
void FUN_800e5330(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6);
void curves_addCurveDef(int param_1);
void curves_countRandomPoints(void);
void FUN_800e5928(int param_1,uint *param_2);
void FUN_800e5b80(void);
void FUN_800e5f40(short *param_1,int param_2);
void FUN_800e60bc(int param_1,int param_2);
void FUN_800e61a0(int param_1,int param_2);
void FUN_800e6410(void);
void FUN_800e6778(void);
void FUN_800e6a30(void);
void FUN_800e6ba0(void);
double FUN_800e6d14(undefined8 param_1,double param_2,double param_3,double param_4,int param_5);
undefined4 *
curves_getCurves(undefined8 param_1,double param_2,int param_3,undefined4 *param_4,int param_5);
void FUN_800e6f68(void);
void FUN_800e7910(undefined4 param_1,uint *param_2);
void FUN_800e79a0(void);
void FUN_800e7f08(uint *param_1,byte param_2,uint param_3,uint param_4,undefined param_5,
                 undefined param_6);
void curves_clear(uint *param_1,undefined param_2,uint param_3,undefined param_4);
uint FUN_800e8024(char param_1,uint param_2);
void gameplay_setDebugOptionEnabled(uint param_1,char param_2);

#endif /* MAIN_DLL_CURVES_H_ */
