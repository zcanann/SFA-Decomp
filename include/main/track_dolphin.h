#ifndef MAIN_TRACK_DOLPHIN_H_
#define MAIN_TRACK_DOLPHIN_H_

#include "ghidra_import.h"

struct TrackBlockDescriptor;
struct TrackTriangle;

void FUN_800602d4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
int FUN_800604ac(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9);
void FUN_8006070c(u64 param_1,double param_2,u32 param_3,u32 param_4,
                 int param_5,float *param_6,u32 param_7,u32 param_8,int param_9);
u32 FUN_80060eec(int param_1,u32 param_2,u32 param_3,int param_4,int param_5,
                 u32 *param_6,float *param_7,int param_8);
int FUN_800614dc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9,u32 param_10);
int FUN_80061a78(u64 param_1,double param_2,double param_3,double param_4,u32 param_5,
                float *param_6,u32 *param_7);
u32
FUN_80061cbc(double param_1,double param_2,double param_3,float *param_4,float *param_5,char param_6
            );
void FUN_8006200c(u32 param_1,u32 param_2,u32 param_3,int *param_4,int param_5,
                 char param_6,char param_7,char param_8);
void FUN_800620e8(u32 param_1,u32 param_2,float *param_3,int *param_4,int *param_5,
                 u32 param_6,u32 param_7,u32 param_8,u8 param_9);
void FUN_800620ec(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_800627a0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u32
FUN_800632d8(u64 param_1,double param_2,double param_3,u32 param_4,float *param_5,
            u32 param_6);
u32
FUN_800632e0(u64 param_1,double param_2,double param_3,u32 param_4,float *param_5,
            u32 *param_6,u32 param_7);
u32
FUN_800632e8(u64 param_1,double param_2,double param_3,u32 param_4,float *param_5,
            u32 param_6);
void FUN_800632f0(u64 param_1,double param_2,u32 param_3,u32 param_4,
                 int *param_5,int param_6);
void FUN_800632f4(u64 param_1,double param_2,double param_3,u32 param_4,
                 u32 param_5,int param_6,u32 param_7);
u32
FUN_800632f8(double param_1,double param_2,float *param_3,float *param_4,float *param_5,
            float *param_6,u8 param_7);
void FUN_8006374c(u32 param_1,u32 param_2,float *param_3,float *param_4,float *param_5
                 ,float *param_6);
void FUN_80063a6c(u64 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,double param_7,u32 param_8,u32 param_9,int *param_10,
                 u32 param_11);
void FUN_80063a70(u32 param_1,u32 param_2,int param_3,int param_4,int param_5,
                 int param_6,int param_7,u32 param_8,char param_9);
void trackDolphin_buildSweptBounds(u32 *boundsOut,float *startPoints,float *endPoints,
                                   float *radii,int pointCount);


/* extern-cleanup: defining-file public prototypes */
int fn_80060C14(int* obj, int triBuf, void* planesOut, int vertsOut, int p7, f32 offX, f32 offZ, int p8, int kindMask);
void objDrawFn_80061f0c(void* cache, void* blockData, int* obj, int slot, void* p7, void* buf48, f32 f);
void fn_800659A8(struct TrackTriangle* triStart, struct TrackTriangle* triEnd, struct TrackBlockDescriptor* desc,
                 f32 qx, f32 qz, int allowDown);
#endif /* MAIN_TRACK_DOLPHIN_H_ */
