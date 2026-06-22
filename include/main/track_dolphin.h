#ifndef MAIN_TRACK_DOLPHIN_H_
#define MAIN_TRACK_DOLPHIN_H_

#include "ghidra_import.h"

void mapBlockRender_setVtxDcrs(int flag, int *obj, int sh, int *bs);
void FUN_8005fab0(int param_1,float *param_2);
void FUN_8005fb68(void);
void FUN_8005fdec(void);
void FUN_8005fdf0(u32 *param_1,u32 *param_2,u32 *param_3,u32 *param_4);
void FUN_8005fe14(int param_1);
void FUN_8005ff38(u16 *param_1,float *param_2);
void FUN_8005ff90(short *param_1,float *param_2);
u32 FUN_8006004c(int param_1);
u32 FUN_80060058(int param_1);
int FUN_80060064(int param_1,u32 param_2);
int FUN_800600b4(int param_1,int param_2);
int FUN_800600c4(int param_1,int param_2);
int FUN_800600d4(int param_1,int param_2);
int FUN_800600e4(int param_1,int param_2);
void FUN_800600f4(void);
void FUN_800601e4(int param_1);
void FUN_800602d4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
int FUN_800604ac(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9);
void FUN_80060650(void);
u32 FUN_8006069c(void);
void FUN_800606a4(u32 *param_1,u32 *param_2);
void FUN_800606a8(void);
void FUN_8006070c(u64 param_1,double param_2,u32 param_3,u32 param_4,
                 int param_5,float *param_6,u32 param_7,u32 param_8,int param_9);
void FUN_80060710(double param_1,float *param_2,float *param_3);
void FUN_80060800(double param_1,float *param_2,float *param_3,u32 *param_4);
void FUN_80060a60(u16 *param_1,int param_2);
void FUN_80060a64(u16 *param_1,int param_2);
void FUN_80060a68(u32 param_1,float *param_2,float *param_3);
u32 FUN_80060eec(int param_1,u32 param_2,u32 param_3,int param_4,int param_5,
                 u32 *param_6,float *param_7,int param_8);
void FUN_80061020(u32 param_1,u32 param_2,u16 *param_3,int param_4);
int FUN_80061024(int param_1,u32 param_2);
void FUN_80061194(void);
u16 FUN_80061198(int param_1,int param_2);
void FUN_80061424(void);
void FUN_80061494(void);
void FUN_800614c4(void);
void FUN_800614d0(u8 param_1);
int FUN_800614dc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                int param_9,u32 param_10);
void FUN_800616a0(int param_1);
void FUN_800616c0(void);
void FUN_800616c4(double param_1,double param_2,double param_3,u32 param_4);
void FUN_80061918(void);
int FUN_80061a78(u64 param_1,double param_2,double param_3,double param_4,u32 param_5,
                float *param_6,u32 *param_7);
void FUN_80061a80(short *param_1,short *param_2,int param_3);
u32
FUN_80061cbc(double param_1,double param_2,double param_3,float *param_4,float *param_5,char param_6
            );
void FUN_80061fc8(int param_1);
void FUN_8006200c(u32 param_1,u32 param_2,u32 param_3,int *param_4,int param_5,
                 char param_6,char param_7,char param_8);
int FUN_80062010(double param_1,double param_2,double param_3,u16 param_4,int param_5);
void FUN_800620e8(u32 param_1,u32 param_2,float *param_3,int *param_4,int *param_5,
                 u32 param_6,u32 param_7,u32 param_8,u8 param_9);
void FUN_800620ec(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_800627a0(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_800631d4(int param_1,int param_2,int param_3);
void FUN_8006325c(void);
u32 FUN_80063298(void);
void FUN_800632cc(void);
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
void FUN_80063a64(void);
void FUN_80063a68(void);
void FUN_80063a6c(u64 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,double param_7,u32 param_8,u32 param_9,int *param_10,
                 u32 param_11);
void FUN_80063a70(u32 param_1,u32 param_2,int param_3,int param_4,int param_5,
                 int param_6,int param_7,u32 param_8,char param_9);
void FUN_80063a74(u32 param_1,u32 param_2,u32 param_3,char param_4);
void trackDolphin_buildSweptBounds(u32 *boundsOut,float *startPoints,float *endPoints,
                                   float *radii,int pointCount);
u32 * trackDolphin_getIntersectionDescriptorTable(u32 *currentIndexOut);
void trackDolphin_getCurrentTrackPoint(u32 **param_1);
void trackDolphin_getCurrentIntersectionList(int *entryCountOut,u32 *entryListOut);
void trackDolphin_initIntersectionBuffers(void);
void FUN_80064030(u32 param_1,u32 param_2,int param_3);
void FUN_80064384(int param_1);


/* extern-cleanup: defining-file public prototypes */
int fn_80060C14(int* obj, int p4, void* p5, int p6, int p7, f32 a, f32 b, int p8, int p9);
void objDrawFn_80061f0c(void* cache, void* blockData, int* obj, int slot, void* p7, void* buf48, f32 f);
void fn_800659A8(f32 a, f32 b, void* p3, void* p4, void* desc, int e);
void initTextures(void);
void fn_80060BB0(void);
void* fn_800606DC(int* obj, int idx);
void* fn_800606FC(int* obj, int idx);
void gxErrorFn_80060b40(void);
void* MapBlock_loadFromFile(int blockId);
void setMapBlockFlag(void);
void objFn_80065604(void);
void setupToRenderMapBlock(int* block, void* posMtx);
void fn_80062894(void);
void fn_80062808(void);
void renderGlows(void);

#endif /* MAIN_TRACK_DOLPHIN_H_ */
