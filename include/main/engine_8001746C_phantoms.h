#ifndef MAIN_ENGINE_8001746C_PHANTOMS_H_
#define MAIN_ENGINE_8001746C_PHANTOMS_H_

/* Empty-stub definitions for the dead v1.1 Ghidra phantom symbols originally
 * defined by placeholder_8001746C.c (object.c graduation, c18f922e2).
 * Included by exactly ONE TU (main/object.c).
 *
 * The 170 stubs that no file referenced have been removed; the ~174 kept here
 * are referenced ONLY by other files' (equally dead) phantom code, retained as
 * the graduation safety net: if a phantom caller is later graduated to real
 * code its reference becomes live and the link needs the stub defined.
 *
 * As of this commit mwld dead-strips both these stubs and their referencing
 * phantom code, so FULL removal is dol-safe TODAY (verified: emptying the
 * header keeps main.dol md5 unchanged). The owner may collapse this header
 * entirely whenever they choose to retire the phantom callers. */

#include "ghidra_import.h"

void FUN_80017448(u32 param_1,u32 param_2,u32 *param_3,float *param_4, float *param_5,u32 param_6) {}
u16 * FUN_80017470(u64 param_1,u64 param_2,u64 param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, u32 param_9) { return 0; }
void FUN_80017480(int param_1,u32 param_2,u32 param_3) {}
void FUN_80017484(u8 param_1,u8 param_2,u8 param_3,u8 param_4) {}
void FUN_80017488(u64 param_1,u64 param_2,u64 param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, int param_9) {}
u32 FUN_8001748c(void) { return 0; }
void FUN_80017494(int param_1,u32 param_2) {}
u32 FUN_80017498(void) { return 0; }
u32 FUN_800174a0(void) { return 0; }
void FUN_800174b8(u64 param_1,u64 param_2,u64 param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8) {}
void FUN_800174d4(u32 param_1) {}
void FUN_800174e8(u64 param_1,u64 param_2,u64 param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8) {}
void FUN_800174f0(u32 param_1) {}
void FUN_800174f4(u64 param_1,u64 param_2,u64 param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, u32 param_9) {}
void FUN_8001750c(int param_1) {}
void FUN_80017510(u64 param_1,double param_2,double param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, int param_9,u32 param_10,u32 param_11,u32 param_12, u32 param_13,u32 param_14,u32 param_15,u32 param_16) {}
void FUN_80017520(u32 *param_1) {}
void FUN_80017524(u32 param_1,u32 param_2,u8 param_3,u8 param_4, u32 param_5) {}
void FUN_8001753c(int param_1,int param_2,short param_3) {}
void FUN_80017540(int param_1) {}
void FUN_80017544(double param_1,int param_2) {}
void FUN_80017548(int param_1,u8 param_2,u8 param_3,u8 param_4, u8 param_5) {}
void FUN_8001754c(u64 param_1,double param_2,double param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, u32 param_9,u32 param_10,u32 param_11,u32 param_12, u32 param_13,u32 param_14,u32 param_15,u32 param_16) {}
void FUN_80017550(int param_1,u32 *param_2,u32 *param_3) {}
int FUN_80017558(int param_1) { return 0; }
u32 FUN_80017570(int param_1) { return 0; }
void FUN_80017580(int param_1,u8 param_2,u8 param_3,u8 param_4, u8 param_5) {}
void FUN_80017584(int param_1,u8 *param_2,u8 *param_3,u8 *param_4, u8 *param_5) {}
void FUN_80017588(int param_1,u8 param_2,u8 param_3,u8 param_4, u8 param_5) {}
void FUN_80017594(int param_1,u8 param_2,u8 param_3,u8 param_4, u8 param_5) {}
void FUN_8001759c(int param_1,u8 param_2,u8 param_3,u8 param_4, u8 param_5) {}
void FUN_800175a0(int param_1,u8 param_2) {}
void FUN_800175b0(int param_1,u32 param_2) {}
void FUN_800175bc(int param_1,u8 param_2) {}
u32 FUN_800175c4(int param_1) { return 0; }
void FUN_800175cc(double param_1,int param_2,char param_3) {}
void FUN_800175d0(double param_1,double param_2,int param_3) {}
void FUN_800175d4(double param_1,double param_2,double param_3,int *param_4) {}
void FUN_800175d8(int param_1,u8 param_2) {}
void FUN_800175ec(double param_1,double param_2,double param_3,int *param_4) {}
void FUN_800175fc(u32 param_1,u32 param_2,int param_3) {}
void FUN_80017600(int param_1,u32 param_2,u32 param_3) {}
void FUN_80017604(void) {}
void FUN_80017608(u8 param_1) {}
void FUN_8001761c(void) {}
void FUN_80017620(u32 param_1) {}
int * FUN_80017624(int param_1,char param_2) { return 0; }
void FUN_8001763c(u64 param_1,double param_2,double param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, u32 param_9,u32 param_10,u32 param_11,u32 param_12, u32 param_13,u32 param_14,u32 param_15,u32 param_16) {}
void FUN_80017640(u64 param_1,double param_2,double param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, u32 param_9,u32 param_10,u32 param_11,u32 param_12, u32 param_13,u32 param_14,u32 param_15,u32 param_16) {}
void FUN_80017648(void) {}
u8 FUN_80017658(int *param_1) { return 0; }
void FUN_80017660(int param_1) {}
void FUN_80017664(u32 param_1) {}
void FUN_80017668(void) {}
void FUN_8001766c(void) {}
int FUN_80017674(void) { return 0; }
void FUN_8001767c(void) {}
u32 FUN_80017680(u32 param_1) { return 0; }
u32 FUN_80017688(u32 param_1) { return 0; }
u32 FUN_80017690(u32 param_1) { return 0; }
void FUN_80017698(u32 param_1,u32 param_2) {}
u32 FUN_8001769c(void) { return 0; }
u32 FUN_800176a8(void) { return 0; }
void FUN_800176b4(u8 param_1) {}
void FUN_800176c0(u8 param_1) {}
void FUN_800176c8(int param_1) {}
void FUN_800176cc(void) {}
int FUN_800176d0(void) { return 0; }
void FUN_800176dc(u64 param_1,double param_2,double param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, u32 param_9,u32 param_10,u32 param_11,u32 param_12, u32 param_13,u32 param_14,u32 param_15,u32 param_16) {}
double FUN_800176f4(double param_1,double param_2,double param_3) { return 0.0; }
void FUN_80017700(u16 *param_1,float *param_2) {}
void FUN_80017704(u32 *param_1,u32 *param_2) {}
double FUN_80017708(float *param_1,float *param_2) { return 0.0; }
void FUN_80017710(float *param_1,float *param_2) {}
double FUN_80017714(float *param_1,float *param_2) { return 0.0; }
void FUN_8001771c(float *param_1,float *param_2) {}
int FUN_80017720(void) { return 0; }
int FUN_80017728(void) { return 0; }
int FUN_80017730(void) { return 0; }
int FUN_80017738(void) { return 0; }
void FUN_80017740(double param_1,double param_2,double param_3,float *param_4) {}
void FUN_80017744(u32 param_1,float *param_2) {}
void FUN_80017748(u16 *param_1,float *param_2) {}
void FUN_8001774c(float *param_1,int param_2) {}
void FUN_80017754(float *param_1,u16 *param_2) {}
u32 FUN_80017758(double param_1,double param_2,float *param_3) { return 0; }
void FUN_8001776c(float *param_1,float *param_2,float *param_3) {}
void FUN_80017778(double param_1,double param_2,double param_3,float *param_4,float *param_5, float *param_6,float *param_7) {}
void FUN_8001777c(float *param_1,float *param_2,float *param_3) {}
void FUN_80017784(float *param_1) {}
void FUN_80017788(float *param_1,float *param_2,float *param_3) {}
void FUN_8001778c(float *param_1) {}
void FUN_80017790(u32 param_1,u32 param_2,int param_3) {}
void FUN_80017794(int param_1) {}
void FUN_80017798(u32 param_1,u32 param_2,int param_3) {}
u32 FUN_8001779c(void) { return 0; }
u32 FUN_800177b4(u32 param_1) { return 0; }
u32 FUN_800177bc(u32 param_1) { return 0; }
int FUN_800177c4(void) { return 0; }
u32 FUN_800177dc(u32 param_1) { return 0; }
int FUN_80017800(u32 param_1) { return 0; }
void FUN_80017810(void) {}
void FUN_80017814(u32 param_1) {}
u32 FUN_80017818(u32 param_1) { return 0; }
u32 FUN_80017824(u32 param_1) { return 0; }
void FUN_8001782c(u8 param_1) {}
int FUN_80017830(int param_1,int param_2) { return 0; }
void FUN_8001789c(u32 param_1,u32 param_2,int *param_3,u8 *param_4) {}
void FUN_800178a0(int param_1,u8 param_2) {}
void FUN_800178a4(double param_1,double param_2,double param_3,int param_4) {}
void FUN_800178ac(int param_1) {}
void FUN_800178b0(u32 *param_1) {}
void FUN_800178b4(void) {}
void FUN_800178b8(int param_1,int param_2,float *param_3) {}
u32 FUN_800178bc(void) { return 0; }
void FUN_800178d0(u32 param_1,u32 param_2,float *param_3) {}
void FUN_800178d4(void) {}
void FUN_800178e4(double param_1,int *param_2,int param_3) {}
void FUN_800178e8(double param_1,int *param_2,int param_3,int param_4,int param_5,u8 param_6) {}
void FUN_800178ec(int *param_1) {}
void FUN_800178f0(u32 param_1,u32 param_2,int param_3,float *param_4,int param_5) {}
int FUN_80017914(int param_1,int param_2) { return 0; }
int FUN_80017924(int param_1,int param_2) { return 0; }
int FUN_8001792c(int param_1,int param_2) { return 0; }
u16 FUN_80017934(int param_1) { return 0; }
void FUN_80017940(u32 param_1,int param_2) {}
int FUN_80017944(int param_1,int param_2) { return 0; }
u32 FUN_8001794c(int param_1) { return 0; }
void FUN_80017954(void) {}
void FUN_80017958(int param_1,u32 param_2) {}
u32 FUN_8001795c(int param_1) { return 0; }
void FUN_80017964(int param_1,u32 param_2) {}
void FUN_80017968(int param_1) {}
void FUN_8001796c(int param_1) {}
int FUN_80017970(int *param_1,int param_2) { return 0; }
int FUN_80017978(int param_1,int param_2) { return 0; }
void FUN_80017988(u32 param_1,u32 param_2,int param_3,u32 param_4) {}
void FUN_800179c8(u32 param_1,u32 param_2,int param_3,u32 *param_4,u32 param_5) {}
void FUN_800179cc(u32 param_1,u32 param_2,int param_3,int *param_4,int param_5) {}
void FUN_80017a00(void) {}
void FUN_80017a04(void) {}
void FUN_80017a0c(int param_1,u8 param_2) {}
void FUN_80017a10(int param_1,u8 param_2) {}
u8 FUN_80017a20(int param_1) { return 0; }
void FUN_80017a28(u32 param_1,u32 param_2,u32 param_3,u32 param_4, u32 param_5,u32 param_6) {}
void FUN_80017a30(int param_1) {}
u8 FUN_80017a34(int param_1) { return 0; }
void FUN_80017a3c(u16 *param_1,u16 param_2) {}
void FUN_80017a40(u16 *param_1,float *param_2,float *param_3) {}
void FUN_80017a48(float *param_1,short *param_2,float *param_3) {}
void FUN_80017a4c(short *param_1,u32 *param_2) {}
void FUN_80017a50(u16 *param_1,float *param_2,char param_3) {}
u32 FUN_80017a54(int param_1) { return 0; }
int FUN_80017a5c(u64 param_1,double param_2,double param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, int param_9,u32 param_10) { return 0; }
void FUN_80017a64(int param_1,u16 param_2) {}
void FUN_80017a68(int param_1) {}
void FUN_80017a6c(int param_1,int param_2,int param_3,int param_4,char param_5,char param_6) {}
void FUN_80017a70(int param_1) {}
void FUN_80017a74(u32 param_1) {}
void FUN_80017a78(int param_1,int param_2) {}
void FUN_80017a7c(int param_1,char param_2) {}
u32 FUN_80017a80(int param_1) { return 0; }
u32 FUN_80017a88(double param_1,double param_2,double param_3,int param_4) { return 0; }
u32 FUN_80017a90(void) { return 0; }
u32 FUN_80017a98(void) { return 0; }
u16 * FUN_80017aa4(u32 param_1,u16 param_2) { return 0; }
void FUN_80017ac8(u64 param_1,u64 param_2,u64 param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, int param_9) {}
void FUN_80017ad0(int param_1) {}
void FUN_80017ae4(u64 param_1,double param_2,double param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8, u32 param_9,u32 param_10,u8 param_11,u32 param_12, u32 *param_13,u32 param_14,u32 param_15,u32 param_16) {}
u32 FUN_80017ae8(void) { return 0; }
int FUN_80017af0(int param_1) { return 0; }
int FUN_80017af8(int param_1) { return 0; }
u32 FUN_80017b00(u32 *param_1,u32 *param_2) { return 0; }
void FUN_80017b10(u64 param_1,u64 param_2,u64 param_3,u64 param_4, u64 param_5,u64 param_6,u64 param_7,u64 param_8) {}

#endif /* MAIN_ENGINE_8001746C_PHANTOMS_H_ */
