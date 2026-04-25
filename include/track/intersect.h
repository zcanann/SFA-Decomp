#ifndef TRACK_INTERSECT_H_
#define TRACK_INTERSECT_H_

#include "ghidra_import.h"

void fn_8006EF38(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7);
void* fn_8006F388(u32 i);
void fn_8006F400(f32 step);
void fn_8006F500(void);
void fn_8006F950(undefined4 param_1,undefined4 param_2,undefined param_3,uint param_4);
void fn_8006FC00(int param_1);
void fn_8006FCCC(void);
undefined4 fn_8006FDF8(int param_1,int param_2,int param_3);
uint fn_8006FED4(void);
void fn_8006FEF8(u32 param_1);
void fn_8006FF00(void);
void fn_8006FF0C(double param_1,double param_2,double param_3,double param_4,double param_5,
                 float *param_6,short *param_7);
void fn_800701A4(f32* x, f32* y, f32* z);
void fn_80070234(f32* param_1);
void fn_800702B8(u32 param_1);
void fn_80070310(u32 param_1, int param_2, u32 param_3);
void fn_800703AC(void);
void fn_800703BC(u8 param_1);
void fn_800703C4(void);
void fn_80070404(f32 a, f32 b);
void fn_800704DC(u8* param_1);
void fn_800704FC(u8 param_1, u8 param_2, u8 param_3);
void fn_80070510(undefined4 param_1,undefined4 param_2,int param_3);
void fn_80070ED4(undefined param_1);
void fn_800717FC(void);
void fn_80071D54(byte *param_1);
void fn_800722B0(double param_1,double param_2,float *param_3,byte *param_4);
void fn_80072DFC(undefined4 param_1,undefined4 param_2,int param_3);
void fn_8007366C(undefined param_1);
void fn_80073AAC(void* texture, u32* colorA, u32* colorB);
undefined4 fn_80073D04(int param_1,int *param_2);
undefined4 fn_80074110(int param_1,int *param_2,int param_3);
void fn_80074518(undefined4 param_1,undefined4 param_2,int param_3);
undefined4 fn_80074D04(int param_1,int *param_2);
void fn_800753B8(int x1, int y1, int x2, int y2, u8* color);
void fn_80075684(u8* color, f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, f32 x4, f32 y4);
void fn_80075A1C(u8* color, f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3);
void fn_80075D5C(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2, int z);
void fn_80075E8C(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2);
void fn_80075FC8(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7,int param_8,int param_9);
void fn_80076510(double param_1,double param_2,int param_3,int param_4);
void fn_8007681C(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7,uint param_8);
void fn_80076D78(undefined4 param_1,undefined4 param_2,int param_3,undefined4 *param_4,uint param_5
                 ,uint param_6);
void fn_8007719C(double param_1,double param_2,int param_3,uint param_4,uint param_5);
void fn_80077604(f32* obj, u32* colorPtr, Mtx mtx);
void fn_8007788C(f32* obj, u32* colorPtr, Mtx mtx);
void fn_80077AD8(double param_1,float *param_2,int param_3,float *param_4);
void fn_80077EF8(undefined4 param_1,undefined4 param_2,float *param_3);
void FUN_80070ec8(void);
void fn_8007880C(void);
void fn_800788DC(void);
void fn_800789AC(void);
void fn_80078A7C(void);
void fn_80078B4C(void);
void fn_80078C1C(void);
void fn_80078DFC(void);
void fn_80078ED0(void);
void fn_80078FA4(void);
void fn_800790AC(void);
void fn_80079180(void);
void fn_80079254(void);
void fn_80079328(void);
void fn_800794E0(void);
void fn_800795E8(void);
void fn_800796F0(void);
void fn_80079804(void);
void fn_800799C0(void);
void fn_800799E4(u8 r, u8 g, u8 b, u8 a);
void fn_80079A24(u8 r, u8 g, u8 b, u8 a);
void fn_80079A64(double param_1,double param_2,byte param_3,char param_4);
void fn_80079E64(double param_1,double param_2,double param_3,undefined param_4,undefined4 param_5,
                 undefined param_6,undefined param_7);
void fn_8007A71C(uint param_1);
void fn_8007AD10(double param_1);
void fn_8007B01C(double param_1,double param_2,double param_3,char param_4,char param_5);
void fn_8007BD8C(int param_1,int param_2);
void fn_8007C3D0(u8 flag);
void fn_8007C664(int param_1);
void fn_8007CAF4(void);
void fn_8007CF7C(void);
void fn_8007D670(void);
void FUN_800723a0(void);
undefined4 fn_8007D72C(void);
void fn_8007D960(u32 param_1);
void fn_8007D988(void);
s32 fn_8007D994(void);
int fn_8007D99C(void);
int fn_8007DB24(int a, int b, int c);
int fn_8007DBC0(int a);
int fn_8007DC5C(int a, int b);
int fn_8007DD04(u8 retry);
int fn_8007DE0C(u8 retry);
void fn_8007DEF0(void);
void fn_8007DF10(u32* buttons, u32* texts, u32* count);
void fn_8007E1AC(int param_1);
void fn_8007E54C(int param_1);
int fn_8007E6D4(u8 slot, int unused, void* src1, void* src2);
int fn_8007E748(int param_1, int param_2, void* dst);

#endif /* TRACK_INTERSECT_H_ */
