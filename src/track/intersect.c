#include "ghidra_import.h"
#include "dolphin/card.h"
#include "dolphin/gx.h"
#include "dolphin/mtx.h"
#include "track/intersect.h"

extern Mtx lbl_80397420;
extern Mtx lbl_80397480;
extern Mtx lbl_803974B0;
extern f32 lbl_803DFB10;
extern f32 fn_80293900(f32 x);

extern undefined4 ABS();
extern undefined4 FUN_8000bb00();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000eba8();
extern undefined4 FUN_8000ef68();
extern undefined4 FUN_8000f56c();
extern undefined4 FUN_8000f7a0();
extern undefined4 FUN_8000f9d4();
extern ushort FUN_8000fa90();
extern ushort FUN_8000fab0();
extern undefined4 FUN_8000fb20();
extern double FUN_8000fc08();
extern double FUN_8000fc3c();
extern undefined4 FUN_80014bf0();
extern undefined4 FUN_80014c98();
extern uint FUN_80014e9c();
extern undefined4 FUN_80014f6c();
extern undefined4 FUN_80015e00();
extern undefined4 FUN_800163fc();
extern void* FUN_800195a8();
extern undefined8 FUN_80019940();
extern int FUN_80019c30();
extern undefined4 FUN_80019c5c();
extern uint FUN_80020078();
extern undefined4 FUN_80020390();
extern undefined4 FUN_800206d8();
extern int FUN_80020800();
extern double FUN_80021434();
extern uint FUN_80022264();
extern undefined4 FUN_800235b0();
extern undefined8 FUN_800238c4();
extern undefined4 FUN_80023d8c();
extern int FUN_800284e8();
extern undefined4 FUN_80028588();
extern undefined4 FUN_80028630();
extern uint FUN_8002bac4();
extern uint FUN_8003bc6c();
extern undefined4 FUN_8004a5b8();
extern undefined4 FUN_8004a9e4();
extern char FUN_8004c3c4();
extern undefined4 FUN_8004c3cc();
extern undefined4 FUN_8004c3e0();
extern undefined4 FUN_8004c460();
extern uint FUN_8005383c();
extern undefined4 FUN_80054ed0();
extern int FUN_800658e4();
extern undefined4 FUN_8006c674();
extern void newshadows_getShadowDirectionTexture(int *textureOut);
extern void newshadows_getSoftShadowTexture(int *textureOut);
extern void newshadows_getShadowRampTexture(int *textureOut);
extern void newshadows_getShadowDiskTexture(int *textureOut);
extern undefined4 FUN_8006c754();
extern void newshadows_getShadowNoiseTexture(int *textureOut);
extern undefined4 FUN_8006c7f4();
extern undefined4 FUN_8006c820();
extern void newshadows_bindShadowRenderTexture(int textureSlot);
extern int newshadows_getShadowRenderTexture(void);
extern int FUN_8006c8c0();
extern void newshadows_flushShadowRenderTargets(void);
extern void newshadows_getShadowNoiseScroll(float *xOffsetOut,float *yOffsetOut);
extern undefined8 FUN_8007e7a0();
extern undefined4 FUN_8007e928();
extern undefined4 FUN_8007e99c();
extern undefined4 FUN_8007e9d0();
extern undefined8 FUN_8007ed98();
extern int FUN_8007fac8();
extern char FUN_80245ff4();
extern undefined4 FUN_802475b8();
extern undefined4 FUN_80247618();
extern undefined4 FUN_8024782c();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247d2c();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f90();
extern undefined4 FUN_80247fb0();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025aa74();
extern undefined4 FUN_8025b94c();
extern undefined4 FUN_8025b9e8();
extern undefined4 FUN_8025bb48();
extern undefined4 FUN_8025bd1c();
extern undefined4 FUN_8025be54();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c428();
extern undefined4 FUN_8025c510();
extern undefined4 FUN_8025c584();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c6b4();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined4 FUN_8025ca38();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025cdec();
extern undefined4 FUN_8025ce6c();
extern undefined4 FUN_8025cee4();
extern undefined4 FUN_8025d6ac();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025d8c4();
extern undefined4 FUN_8025f458();
extern int FUN_8026218c();
extern int FUN_802622ac();
extern int FUN_80262b10();
extern undefined4 FUN_80262bf4();
extern int FUN_8026343c();
extern undefined4 FUN_80263888();
extern int FUN_80264624();
extern int FUN_80264b4c();
extern int FUN_80286718();
extern undefined2 FUN_802867ac();
extern undefined4 FUN_802867f8();
extern char FUN_80286820();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802928f4();
extern double FUN_80293900();
extern undefined4 FUN_80294224();
extern undefined4 FUN_802943c4();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern undefined4 SQRT();

extern undefined4 DAT_802c2628;
extern undefined4 DAT_802c262c;
extern undefined4 DAT_802c2630;
extern undefined4 DAT_802c2634;
extern undefined4 DAT_802c2638;
extern undefined4 DAT_802c263c;
extern undefined4 DAT_802c2640;
extern undefined4 DAT_802c2644;
extern undefined4 DAT_802c2648;
extern undefined4 DAT_802c264c;
extern undefined4 DAT_802c2650;
extern undefined4 DAT_802c2654;
extern undefined4 DAT_802c2658;
extern undefined4 DAT_802c265c;
extern undefined4 DAT_802c2660;
extern undefined4 DAT_802c2664;
extern undefined4 DAT_802c2668;
extern undefined4 DAT_802c266c;
extern undefined4 DAT_802c2670;
extern undefined4 DAT_802c2674;
extern undefined4 DAT_802c2678;
extern undefined4 DAT_802c267c;
extern undefined4 DAT_802c2680;
extern undefined4 DAT_802c2684;
extern undefined4 DAT_802c2688;
extern undefined4 DAT_802c268c;
extern undefined4 DAT_802c2690;
extern undefined4 DAT_802c2694;
extern undefined4 DAT_802c2698;
extern undefined4 DAT_802c269c;
extern undefined4 DAT_802c26a0;
extern undefined4 DAT_802c26a4;
extern undefined4 DAT_802c26a8;
extern undefined4 DAT_802c26ac;
extern undefined4 DAT_802c26b0;
extern undefined4 DAT_802c26b4;
extern undefined4 DAT_802c26b8;
extern undefined4 DAT_802c26bc;
extern undefined4 DAT_802c26c0;
extern undefined4 DAT_802c26c4;
extern undefined4 DAT_802c26c8;
extern undefined4 DAT_802c26cc;
extern undefined4 DAT_802c26d0;
extern undefined4 DAT_802c26d4;
extern undefined4 DAT_802c26d8;
extern undefined4 DAT_802c26dc;
extern undefined4 DAT_802c26e0;
extern undefined4 DAT_802c26e4;
extern undefined4 DAT_802c26e8;
extern undefined4 DAT_802c26ec;
extern undefined4 DAT_802c26f0;
extern undefined4 DAT_802c26f4;
extern undefined4 DAT_802c26f8;
extern undefined4 DAT_802c26fc;
extern undefined4 DAT_802c7b54;
extern undefined4 DAT_802c8e0a;
extern undefined2 DAT_8030f470;
extern undefined2 DAT_8030f484;
extern undefined2 DAT_8030f498;
extern undefined2 DAT_8030f4ac;
extern undefined2 DAT_8030f4c0;
extern undefined2 DAT_8030f4d4;
extern undefined2 DAT_8030f4e8;
extern undefined2 DAT_8030f4fc;
extern undefined2 DAT_8030f510;
extern undefined4 DAT_8030f524;
extern undefined4 DAT_8030f5d0;
extern undefined4 DAT_8030f5e8;
extern undefined4 DAT_8030f600;
extern undefined4 DAT_8030f618;
extern undefined4 DAT_8030f630;
extern undefined4 DAT_8030f648;
extern undefined4 DAT_8030f660;
extern undefined4 DAT_80392a20;
extern undefined4 DAT_80392a24;
extern undefined4 DAT_80392a28;
extern undefined4 DAT_80392a2c;
extern undefined4 DAT_80392a30;
extern undefined4 DAT_80392a34;
extern undefined4 DAT_80392a38;
extern undefined4 DAT_80392a3c;
extern undefined DAT_80392a40;
extern undefined4 DAT_80392a44;
extern undefined4 DAT_80392a48;
extern undefined4 DAT_80392a4c;
extern undefined4 DAT_80392a4e;
extern undefined4 DAT_80392a4f;
extern undefined4 DAT_80393a40;
extern undefined4 DAT_80393a44;
extern undefined4 DAT_80393a48;
extern undefined4 DAT_80393a4c;
extern undefined4 DAT_80393a50;
extern undefined4 DAT_80393a54;
extern undefined4 DAT_80393a58;
extern undefined4 DAT_80393a5c;
extern undefined4 DAT_80393a60;
extern undefined4 DAT_80393a64;
extern undefined4 DAT_80393a68;
extern undefined4 DAT_80393a6c;
extern undefined4 DAT_80393a70;
extern undefined4 DAT_80393a72;
extern undefined4 DAT_80393a73;
extern undefined4 DAT_80393a74;
extern undefined2 DAT_80397240;
extern undefined4 DAT_80397244;
extern undefined4 DAT_80397330;
extern undefined4 DAT_80397332;
extern undefined4 DAT_80397338;
extern undefined4 DAT_80397420;
extern undefined4 DAT_80397480;
extern undefined4 DAT_803974b0;
extern undefined4 DAT_803974e0;
extern undefined4 DAT_80397520;
extern undefined4 DAT_80397560;
extern undefined4 DAT_803dc084;
extern undefined4 DAT_803dc2d8;
extern undefined4 DAT_803dc2d9;
extern undefined4 DAT_803dc2dc;
extern undefined4 DAT_803dc2e0;
extern undefined4 DAT_803dc2e4;
extern undefined4 DAT_803dc2e8;
extern undefined4 DAT_803dc2ec;
extern undefined4 DAT_803dc2f0;
extern undefined4 DAT_803dc2f4;
extern undefined4 DAT_803dc2f8;
extern undefined4 DAT_803dc2fc;
extern undefined4 DAT_803dc300;
extern undefined4 DAT_803dc304;
extern undefined4 DAT_803dc308;
extern undefined4 DAT_803dc31c;
extern undefined4 DAT_803dc330;
extern undefined4 DAT_803dc334;
extern undefined4 DAT_803dc338;
extern undefined4 DAT_803dc33c;
extern undefined4 DAT_803dc340;
extern undefined4 DAT_803dc344;
extern undefined4 DAT_803dc348;
extern undefined4 DAT_803dc34c;
extern undefined4 DAT_803dc350;
extern undefined4 DAT_803dc354;
extern undefined4 DAT_803dc358;
extern undefined4 DAT_803dc360;
/* Narrow-typed aliases for sbss/sdata state vars touched by the small
 * helpers below. */
extern u8 lbl_803DC2D9;
extern s32 lbl_803DC360;
extern u32 lbl_803DDC84;
extern u8 lbl_803DDC99;
extern u8 lbl_803DDC9A;
extern GXColor lbl_803DDC9C;
extern u8 lbl_803DDC88;
extern u8 lbl_803DDC89;
extern u8 lbl_803DDC8A;
extern u8 lbl_803DDC8B;
extern u32 lbl_803DDCB0;
extern u32 lbl_803DDCAC;
extern u32 lbl_803DDCA8;
extern u8 lbl_803DDCD9;
extern u32 lbl_803DDCC8;
extern u32 lbl_803DDCCC;
extern u32 lbl_803DDCD0;
extern u32 lbl_803DDCD4;
extern u8 lbl_803DDC91;
extern f32 lbl_803DDCA0;
extern f32 lbl_803DDCA4;
extern f32 lbl_803DDCB4;
extern f32 lbl_803DDCB8;
extern undefined4 DAT_803dc364;
extern undefined4 DAT_803dc368;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd718;
extern undefined4 DAT_803ddc70;
extern undefined4 DAT_803ddc74;
extern undefined4 DAT_803ddc78;
extern undefined4 DAT_803ddc79;
extern undefined4 DAT_803ddc7a;
extern undefined4 DAT_803ddc80;
extern undefined4 DAT_803ddc82;
extern undefined4 DAT_803ddc84;
extern undefined4 DAT_803ddc88;
extern undefined4 DAT_803ddc89;
extern undefined4 DAT_803ddc8a;
extern undefined4 DAT_803ddc8b;
extern undefined4 DAT_803ddc90;
extern undefined4 DAT_803ddc91;
extern undefined4 DAT_803ddc92;
extern undefined4 DAT_803ddc94;
extern undefined4 DAT_803ddc98;
extern undefined4 DAT_803ddc99;
extern undefined4 DAT_803ddc9a;
extern undefined4 DAT_803ddc9c;
extern undefined4 DAT_803ddca8;
extern undefined4 DAT_803ddcac;
extern undefined4 DAT_803ddcb0;
extern undefined4 DAT_803ddcbc;
extern undefined4 DAT_803ddcc0;
extern undefined4 DAT_803ddcc8;
extern undefined4 DAT_803ddccc;
extern undefined4 DAT_803ddcd0;
extern undefined4 DAT_803ddcd4;
extern undefined4 DAT_803ddcd8;
extern undefined4 DAT_803ddcd9;
extern undefined4 DAT_803ddcda;
extern undefined4 DAT_803dfb20;
extern undefined4 DAT_803dfb24;
extern undefined4 DAT_803dfb28;
extern undefined4 DAT_803dfb2c;
extern undefined4 DAT_803dfb30;
extern undefined4 DAT_803dfb32;
extern undefined4 DAT_803dfb34;
extern undefined4 DAT_803dfb38;
extern undefined4 DAT_803dfb3c;
extern undefined4 DAT_803dfb40;
extern undefined4 DAT_803dfb44;
extern undefined4 DAT_803dfb48;
extern undefined4 DAT_803dfb4c;
extern undefined4 DAT_803dfb50;
extern undefined4 DAT_803dfb54;
extern undefined4 DAT_803e90d0;
extern undefined4 DAT_803e90d4;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803dfab0;
extern f64 DOUBLE_803dfad0;
extern f64 DOUBLE_803dfb80;
extern f64 DOUBLE_803dfb90;
extern f64 DOUBLE_803dfb98;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc30c;
extern f32 FLOAT_803dc310;
extern f32 FLOAT_803dc314;
extern f32 FLOAT_803dc318;
extern f32 FLOAT_803dc320;
extern f32 FLOAT_803dc324;
extern f32 FLOAT_803dc328;
extern f32 FLOAT_803dc32c;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803ddc8c;
extern f32 FLOAT_803ddca0;
extern f32 FLOAT_803ddca4;
extern f32 FLOAT_803ddcb4;
extern f32 FLOAT_803ddcb8;
extern f32 FLOAT_803dfaa0;
extern f32 FLOAT_803dfaa4;
extern f32 FLOAT_803dfaa8;
extern f32 FLOAT_803dfab8;
extern f32 FLOAT_803dfabc;
extern f32 FLOAT_803dfac0;
extern f32 FLOAT_803dfac4;
extern f32 FLOAT_803dfac8;
extern f32 FLOAT_803dfad8;
extern f32 FLOAT_803dfadc;
extern f32 FLOAT_803dfae0;
extern f32 FLOAT_803dfae4;
extern f32 FLOAT_803dfaf4;
extern f32 FLOAT_803dfaf8;
extern f32 FLOAT_803dfafc;
extern f32 FLOAT_803dfb00;
extern f32 FLOAT_803dfb10;
extern f32 FLOAT_803dfb18;
extern f32 FLOAT_803dfb1c;
extern f32 FLOAT_803dfb58;
extern f32 FLOAT_803dfb5c;
extern f32 FLOAT_803dfb60;
extern f32 FLOAT_803dfb64;
extern f32 FLOAT_803dfb68;
extern f32 FLOAT_803dfb6c;
extern f32 FLOAT_803dfb70;
extern f32 FLOAT_803dfb74;
extern f32 FLOAT_803dfb78;
extern f32 FLOAT_803dfb88;
extern f32 FLOAT_803dfba0;
extern f32 FLOAT_803dfba4;
extern f32 FLOAT_803dfba8;
extern f32 FLOAT_803dfbac;
extern f32 FLOAT_803dfbb0;
extern f32 FLOAT_803dfbb4;
extern f32 FLOAT_803dfbb8;
extern f32 FLOAT_803dfbbc;
extern f32 FLOAT_803dfbc0;
extern f32 FLOAT_803dfbc4;
extern f32 FLOAT_803dfbc8;
extern f32 FLOAT_803dfbcc;
extern f32 FLOAT_803dfbd0;
extern f32 FLOAT_803dfbd4;
extern f32 FLOAT_803dfbd8;
extern f32 FLOAT_803dfbdc;
extern f32 FLOAT_803dfbe0;
extern f32 FLOAT_803dfbe4;
extern f32 FLOAT_803dfbe8;
extern f32 FLOAT_803dfbec;
extern f32 FLOAT_803dfbf4;
extern f32 FLOAT_803dfbf8;
extern f32 FLOAT_803dfbfc;
extern f32 FLOAT_803dfc00;
extern f32 FLOAT_803dfc04;
extern f32 FLOAT_803dfc08;
extern f32 FLOAT_803dfc10;
extern f32 FLOAT_803dfc14;
extern undefined4 _DAT_803dc2dc;
extern undefined4 _DAT_803dc2e0;
extern undefined4 _DAT_803dc2e8;
extern undefined4 _DAT_803dc354;

/*
 * --INFO--
 *
 * Function: FUN_8006f0b4
 * EN v1.0 Address: 0x8006F0B4
 * EN v1.0 Size: 1224b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006f0b4(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7)
{
}

/*
 * --INFO--
 *
 * Function: fn_8006F504
 * EN v1.0 Address: 0x8006F504
 * EN v1.0 Size: 120b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void* fn_8006F504(u32 i)
{
    extern u8 lbl_8030F470[];
    u8* base = lbl_8030F470;
    switch (i) {
        case 0:  return base;
        case 1:  return base + 0x14;
        case 2:  return base + 0x3C;
        case 3:  return base + 0x64;
        case 4:  return base + 0x50;
        case 5:  return base + 0x78;
        case 6:  return base + 0x8C;
        case 7:  return base + 0xA0;
        case 10:
        case 8:  return base + 0x28;
        default: return base + 0x28;
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8006f57c
 * EN v1.0 Address: 0x8006F57C
 * EN v1.0 Size: 256b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* EN v1.0 Size: 256b - 77% match. Per-iteration byte decrement:
 *   if (b != 0) {
 *     v = (f32)(u32)b - step;
 *     if (v <= 0) b = 0; else b = (u8)v;
 *   }
 * for 256 rows in two parallel arrays. MWCC CSEs the conversion
 * expression (v) between the compare and the store, emitting a
 * single fctiwz on cached f2. Target recomputes the full
 * stw/lfd/fsubs sequence before the second use, which suggests
 * retail source had a variable reassignment between the two uses
 * (see Ghidra: local_18 reassigned before the else-branch store).
 * Can't reproduce the re-store without __asm. */
#pragma peephole off
#pragma scheduling off
void fn_8006F57C(f32 step)
{
    int i;
    u8* a;
    u8* b;
    extern u8 lbl_80393A40[];
    extern u8 lbl_80392A40[];

    a = lbl_80393A40;
    b = lbl_80392A40;
    for (i = 0; i < 256; i++) {
        if (a[0x33] != 0) {
            if ((f32)(u32)a[0x33] - step <= 0.0f) {
                a[0x33] = 0;
            } else {
                a[0x33] = (u8)(s32)((f32)(u32)a[0x33] - step);
            }
        }
        if (b[0x0E] != 0) {
            if ((f32)(u32)b[0x0E] - step <= 0.0f) {
                b[0x0E] = 0;
            } else {
                b[0x0E] = (u8)(s32)((f32)(u32)b[0x0E] - step);
            }
        }
        a += 0x38;
        b += 0x10;
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8006f67c
 * EN v1.0 Address: 0x8006F67C
 * EN v1.0 Size: 1104b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006f67c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8006facc
 * EN v1.0 Address: 0x8006FACC
 * EN v1.0 Size: 688b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006facc(undefined4 param_1,undefined4 param_2,undefined param_3,uint param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  uint uVar7;
  short *psVar8;
  int iVar9;
  float *pfVar10;
  double dVar11;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar12;
  float fStack_58;
  float afStack_54 [3];
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar12 = FUN_80286840();
  psVar8 = (short *)((ulonglong)uVar12 >> 0x20);
  pfVar10 = (float *)uVar12;
  if (psVar8[0x22] == 1) {
    DAT_803ddc70 = *(byte *)((int)psVar8 + 0xad);
  }
  else if (psVar8[0x23] == 0x416) {
    DAT_803ddc70 = 3;
  }
  iVar9 = FUN_800658e4((double)*(float *)(psVar8 + 6),(double)*(float *)(psVar8 + 8),
                       (double)*(float *)(psVar8 + 10),psVar8,&fStack_58,afStack_54,0);
  if (iVar9 == 0) {
    if ((param_4 & 0xff) == 1) {
      iVar9 = (uint)DAT_803ddc78 * 0x10;
      *(float *)(&DAT_80392a40 + iVar9) = *pfVar10;
      *(float *)(&DAT_80392a44 + iVar9) = FLOAT_803dfabc + pfVar10[1];
      *(float *)(&DAT_80392a48 + iVar9) = pfVar10[2];
      *(short *)(&DAT_80392a4c + iVar9) = *psVar8;
      (&DAT_80392a4e)[iVar9] = 0xff;
      (&DAT_80392a4f)[iVar9] = param_3;
      uVar7 = DAT_803ddc78 + 1;
      DAT_803ddc78 = (byte)uVar7;
      if (0xff < (uVar7 & 0xff)) {
        DAT_803ddc78 = 0;
      }
    }
    FUN_80247ef8(afStack_54,afStack_54);
    local_3c = FLOAT_803dfab8;
    local_38 = FLOAT_803dfaa0;
    local_34 = FLOAT_803dfaa0;
    dVar11 = FUN_80247f90(afStack_54,&local_3c);
    if ((double)FLOAT_803dfad8 <= ABS(dVar11)) {
      local_3c = FLOAT_803dfaa0;
      local_34 = FLOAT_803dfab8;
    }
    FUN_80247fb0(afStack_54,&local_3c,&local_48);
    FUN_80247fb0(&local_48,afStack_54,&local_3c);
    FUN_80247ef8(&local_3c,&local_3c);
    FUN_80247ef8(&local_48,&local_48);
    dVar11 = (double)(float)(&DAT_80392a20)[DAT_803ddc70];
    FUN_80247edc(dVar11,&local_3c,&local_3c);
    FUN_80247edc(dVar11,&local_48,&local_48);
    fVar1 = *pfVar10;
    fVar2 = pfVar10[1];
    fVar3 = pfVar10[2];
    fVar4 = fVar1 - local_3c;
    uVar7 = (uint)DAT_803ddc79;
    iVar9 = uVar7 * 0x38;
    (&DAT_80393a40)[uVar7 * 0xe] = fVar4 - local_48;
    fVar5 = fVar2 - local_38;
    (&DAT_80393a44)[uVar7 * 0xe] = fVar5 - local_44;
    fVar6 = fVar3 - local_34;
    (&DAT_80393a48)[uVar7 * 0xe] = fVar6 - local_40;
    fVar1 = fVar1 + local_3c;
    (&DAT_80393a4c)[uVar7 * 0xe] = fVar1 - local_48;
    fVar2 = fVar2 + local_38;
    (&DAT_80393a50)[uVar7 * 0xe] = fVar2 - local_44;
    fVar3 = fVar3 + local_34;
    (&DAT_80393a54)[uVar7 * 0xe] = fVar3 - local_40;
    (&DAT_80393a58)[uVar7 * 0xe] = local_48 + fVar1;
    (&DAT_80393a5c)[uVar7 * 0xe] = local_44 + fVar2;
    (&DAT_80393a60)[uVar7 * 0xe] = local_40 + fVar3;
    (&DAT_80393a64)[uVar7 * 0xe] = local_48 + fVar4;
    (&DAT_80393a68)[uVar7 * 0xe] = local_44 + fVar5;
    (&DAT_80393a6c)[uVar7 * 0xe] = local_40 + fVar6;
    (&DAT_80393a70)[uVar7 * 0x1c] = -*psVar8;
    (&DAT_80393a72)[iVar9] = (char)param_4;
    (&DAT_80393a73)[iVar9] = 0xff;
    (&DAT_80393a74)[iVar9] = param_3;
    DAT_803ddc79 = (byte)(uVar7 + 1);
    if (0xff < (uVar7 + 1 & 0xff)) {
      DAT_803ddc79 = 0;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006fd7c
 * EN v1.0 Address: 0x8006FD7C
 * EN v1.0 Size: 204b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_8006FD7C(int param_1)
{
    int i;
    u8* a;
    u8* b;
    extern u8 lbl_80393A40[];
    extern u8 lbl_80392A40[];
    extern u8 lbl_803DDC78;
    extern u8 lbl_803DDC79;
    extern u8 lbl_803DDC7A;

    lbl_803DDC7A = (u8)param_1;
    if (param_1 != 0) {
        return;
    }
    a = lbl_80393A40;
    b = lbl_80392A40;
    for (i = 0; i < 16; i++) {
        a[0x033] = 0;  b[0x0E] = 0;
        a[0x06B] = 0;  b[0x1E] = 0;
        a[0x0A3] = 0;  b[0x2E] = 0;
        a[0x0DB] = 0;  b[0x3E] = 0;
        a[0x113] = 0;  b[0x4E] = 0;
        a[0x14B] = 0;  b[0x5E] = 0;
        a[0x183] = 0;  b[0x6E] = 0;
        a[0x1BB] = 0;  b[0x7E] = 0;
        a += 0x1C0;
        b += 0x80;
        a[0x033] = 0;  b[0x0E] = 0;
        a[0x06B] = 0;  b[0x1E] = 0;
        a[0x0A3] = 0;  b[0x2E] = 0;
        a[0x0DB] = 0;  b[0x3E] = 0;
        a[0x113] = 0;  b[0x4E] = 0;
        a[0x14B] = 0;  b[0x5E] = 0;
        a[0x183] = 0;  b[0x6E] = 0;
        a[0x1BB] = 0;  b[0x7E] = 0;
        a += 0x1C0;
        b += 0x80;
    }
    lbl_803DDC79 = 0;
    lbl_803DDC78 = 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8006fe48
 * EN v1.0 Address: 0x8006FE48
 * EN v1.0 Size: 300b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_8006FE48(void)
{
    extern u8 lbl_80392A20[];
    extern f32 lbl_803DFADC, lbl_803DFAE0, lbl_803DFAE4;
    extern u32 fn_80054ED0(int);
    extern u32 lbl_803DDC74;
    extern u8 lbl_803DDC78, lbl_803DDC79, lbl_803DDC7A;
    int i;
    u8* base = lbl_80392A20;
    u8* a = base + 0x1020;
    u8* b = base + 0x0020;

    for (i = 0; i < 16; i++) {
        a[0x033] = 0; b[0x0E] = 0;
        a[0x06B] = 0; b[0x1E] = 0;
        a[0x0A3] = 0; b[0x2E] = 0;
        a[0x0DB] = 0; b[0x3E] = 0;
        a[0x113] = 0; b[0x4E] = 0;
        a[0x14B] = 0; b[0x5E] = 0;
        a[0x183] = 0; b[0x6E] = 0;
        a[0x1BB] = 0; b[0x7E] = 0;
        a[0x1F3] = 0; b[0x8E] = 0;
        a[0x22B] = 0; b[0x9E] = 0;
        a[0x263] = 0; b[0xAE] = 0;
        a[0x29B] = 0; b[0xBE] = 0;
        a[0x2D3] = 0; b[0xCE] = 0;
        a[0x30B] = 0; b[0xDE] = 0;
        a[0x343] = 0; b[0xEE] = 0;
        a[0x37B] = 0; b[0xFE] = 0;
        a += 0x380;
        b += 0x100;
    }
    *(u32*)(base + 0x10) = fn_80054ED0(0x19);
    *(u32*)(base + 0x14) = fn_80054ED0(0x18);
    *(u32*)(base + 0x18) = fn_80054ED0(0x1A);
    *(u32*)(base + 0x1C) = fn_80054ED0(0x646);
    *(f32*)(base + 0x00) = lbl_803DFADC;
    *(f32*)(base + 0x04) = lbl_803DFAE0;
    *(f32*)(base + 0x08) = lbl_803DFAE0;
    *(f32*)(base + 0x0C) = lbl_803DFAE4;
    lbl_803DDC7A = 0;
    lbl_803DDC79 = 0;
    lbl_803DDC78 = 0;
    lbl_803DDC74 = 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8006ff74
 * EN v1.0 Address: 0x8006FF74
 * EN v1.0 Size: 220b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8006ff74(int param_1,int param_2,int param_3)
{
  bool bVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  
  bVar1 = false;
  if ((((-1 < param_1) && (param_1 < 0x280)) && (-1 < param_2)) && (param_2 < 0x1e0)) {
    bVar1 = true;
  }
  if (!bVar1) {
    return 0;
  }
  if (param_1 < 0x10) {
    param_1 = 0x10;
  }
  if (param_2 < 6) {
    param_2 = 6;
  }
  uVar4 = (uint)DAT_803ddc80;
  if (uVar4 < 0x14) {
    (&DAT_80397330)[uVar4 * 6] = (short)param_1;
    (&DAT_80397332)[uVar4 * 6] = (short)param_2;
    (&DAT_80397338)[uVar4 * 3] = param_3;
    DAT_803ddc80 = DAT_803ddc80 + 1;
  }
  iVar3 = 0;
  puVar2 = &DAT_80397240;
  uVar4 = (uint)DAT_803ddc82;
  while( true ) {
    if (uVar4 == 0) {
      return 0;
    }
    if (param_3 == *(int *)(puVar2 + 4)) break;
    puVar2 = puVar2 + 6;
    iVar3 = iVar3 + 1;
    uVar4 = uVar4 - 1;
  }
  return (&DAT_80397244)[iVar3 * 3];
}

/*
 * --INFO--
 *
 * Function: FUN_80070050
 * EN v1.0 Address: 0x80070050
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
uint fn_80070050(void)
{
    u32 v = lbl_803DDC84;
    if (v != 0) {
        return v | (v << 16);
    }
    return 0x01E00280;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80070074
 * EN v1.0 Address: 0x80070074
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80070074(u32 param_1)
{
    lbl_803DDC84 = param_1;
}

/*
 * --INFO--
 *
 * Function: FUN_8007007c
 * EN v1.0 Address: 0x8007007C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007007C(void)
{
    lbl_803DDC84 = 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80070088
 * EN v1.0 Address: 0x80070088
 * EN v1.0 Size: 664b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80070088(double param_1,double param_2,double param_3,double param_4,double param_5,
                 float *param_6,short *param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80070320
 * EN v1.0 Address: 0x80070320
 * EN v1.0 Size: 144b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80070320(f32* x, f32* y, f32* z)
{
    f32 scale;
    f32 len;

    len = fn_80293900(*z * *z + (*x * *x + *y * *y));
    scale = lbl_803DFB10 / len;
    *x = *x * scale;
    *y = *y * scale;
    *z = *z * scale;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_800703b0
 * EN v1.0 Address: 0x800703B0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803DFB18;
extern f32 lbl_803DFB1C;

/* EN v1.0 Size: 132b - 74% match. 4x4 identity fill. Remaining diff:
 * target uses 'li r0, N; cmpw r4, r0' per column, mine uses 'cmpwi
 * r4, N' — MWCC always folds the integer literal into the compare
 * immediate form. The +4 extra li instructions explain the 116 vs
 * 132 byte discrepancy. Not crackable without materializing the
 * comparison indices via a global/volatile, which would break other
 * matches. */
#pragma optimize_for_size on
void fn_800703B0(f32* param_1)
{
    int i;
    f32 zero = lbl_803DFB1C;
    f32 one = lbl_803DFB18;
    for (i = 0; i < 4; i++) {
        if (i == 0) param_1[0] = one; else param_1[0] = zero;
        if (i == 1) param_1[1] = one; else param_1[1] = zero;
        if (i == 2) param_1[2] = one; else param_1[2] = zero;
        if (i == 3) param_1[3] = one; else param_1[3] = zero;
        param_1 += 4;
    }
}
#pragma optimize_for_size reset

/*
 * --INFO--
 *
 * Function: FUN_80070434
 * EN v1.0 Address: 0x80070434
 * EN v1.0 Size: 88b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80070434(u32 param_1)
{
    extern void GXSetZCompLoc();
    if ((u32)lbl_803DDC91 != (param_1 & 0xff) || lbl_803DDC99 == 0) {
        GXSetZCompLoc(param_1);
        lbl_803DDC91 = (u8)param_1;
        lbl_803DDC99 = 1;
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007048c
 * EN v1.0 Address: 0x8007048C
 * EN v1.0 Size: 156b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_8007048C(u32 param_1, int param_2, u32 param_3)
{
    extern void GXSetZMode();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    extern u8 lbl_803DDC9A;

    if ((u32)lbl_803DDC98 != (param_1 & 0xff) ||
        lbl_803DDC94 != param_2 ||
        (u32)lbl_803DDC92 != (param_3 & 0xff) ||
        lbl_803DDC9A == 0) {
        GXSetZMode(param_1, param_2, param_3);
        lbl_803DDC98 = (u8)param_1;
        lbl_803DDC94 = param_2;
        lbl_803DDC92 = (u8)param_3;
        lbl_803DDC9A = 1;
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80070528
 * EN v1.0 Address: 0x80070528
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80070528(void)
{
    lbl_803DDC9A = 0;
    lbl_803DDC99 = 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80070538
 * EN v1.0 Address: 0x80070538
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80070538(u8 param_1)
{
    lbl_803DC2D9 = param_1;
}

/*
 * --INFO--
 *
 * Function: FUN_80070540
 * EN v1.0 Address: 0x80070540
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80070540(void)
{
    GXColor c = lbl_803DDC9C;
    GXSetFog(GX_FOG_PERSP_EXP, lbl_803DDCA4, lbl_803DDCA0, lbl_803DDCB8, lbl_803DDCB4, c);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80070580
 * EN v1.0 Address: 0x80070580
 * EN v1.0 Size: 216b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80070580(f32 a, f32 b)
{
    extern f32 fn_8000FC3C(void);
    extern f32 fn_8000FC08(void);
    extern f32 lbl_803DFB58;
    extern f32 lbl_803DFB5C;
    extern f32 lbl_803DFB60;
    extern f32 lbl_803DDCA0, lbl_803DDCA4, lbl_803DDCB4, lbl_803DDCB8;
    f32 xc, yc, x, y, range;
    GXColor c;

    lbl_803DDCB8 = fn_8000FC3C();
    lbl_803DDCB4 = fn_8000FC08();

    x = lbl_803DFB58 * a;
    y = lbl_803DFB58 * b;

    xc = lbl_803DFB5C;
    if (x >= lbl_803DFB5C) {
        xc = x;
        if (x > lbl_803DFB60) {
            xc = lbl_803DFB60;
        }
    }
    yc = lbl_803DFB5C;
    if (y >= lbl_803DFB5C) {
        yc = y;
        if (y > lbl_803DFB60) {
            yc = lbl_803DFB60;
        }
    }

    range = lbl_803DDCB4 - lbl_803DDCB8;
    lbl_803DDCA4 = xc * range + lbl_803DDCB8;
    lbl_803DDCA0 = yc * range + lbl_803DDCB8;
    c = lbl_803DDC9C;
    GXSetFog(GX_FOG_PERSP_EXP, lbl_803DDCA4, lbl_803DDCA0, lbl_803DDCB8, lbl_803DDCB4, c);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80070658
 * EN v1.0 Address: 0x80070658
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80070658(u8* param_1)
{
    param_1[0] = lbl_803DDC9C.r;
    param_1[1] = lbl_803DDC9C.g;
    param_1[2] = lbl_803DDC9C.b;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80070678
 * EN v1.0 Address: 0x80070678
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80070678(u8 param_1, u8 param_2, u8 param_3)
{
    lbl_803DDC9C.r = param_1;
    lbl_803DDC9C.g = param_2;
    lbl_803DDC9C.b = param_3;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007068c
 * EN v1.0 Address: 0x8007068C
 * EN v1.0 Size: 2500b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007068c(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80071050
 * EN v1.0 Address: 0x80071050
 * EN v1.0 Size: 2344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80071050(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80071978
 * EN v1.0 Address: 0x80071978
 * EN v1.0 Size: 1368b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80071978(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80071ed0
 * EN v1.0 Address: 0x80071ED0
 * EN v1.0 Size: 1372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80071ed0(byte *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007242c
 * EN v1.0 Address: 0x8007242C
 * EN v1.0 Size: 2892b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007242c(double param_1,double param_2,float *param_3,byte *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80072f78
 * EN v1.0 Address: 0x80072F78
 * EN v1.0 Size: 2160b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80072f78(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800737e8
 * EN v1.0 Address: 0x800737E8
 * EN v1.0 Size: 1088b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800737e8(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80073c28
 * EN v1.0 Address: 0x80073C28
 * EN v1.0 Size: 600b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80073C28(void* texture, u32* colorA, u32* colorB)
{
    extern void fn_8004C460(void*, int);
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    fn_8004C460(texture, 0);
    GXSetTevKColor(0, *(GXColor*)colorA);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevColor(1, *(GXColor*)colorB);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevColorIn(0, 0xF, 8, 0xE, 2);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetBlendMode(1, 4, 1, 5);
    if ((u32)lbl_803DDC98 != 1 || lbl_803DDC94 != 3 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DDC98 = 1;
        lbl_803DDC94 = 3;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    if ((u32)lbl_803DDC91 != 1 || lbl_803DDC99 == 0) {
        GXSetZCompLoc(1);
        lbl_803DDC91 = 1;
        lbl_803DDC99 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(2);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80073e80
 * EN v1.0 Address: 0x80073E80
 * EN v1.0 Size: 1036b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80073e80(int param_1,int *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8007428c
 * EN v1.0 Address: 0x8007428C
 * EN v1.0 Size: 1032b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8007428c(int param_1,int *param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80074694
 * EN v1.0 Address: 0x80074694
 * EN v1.0 Size: 2028b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80074694(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80074e80
 * EN v1.0 Address: 0x80074E80
 * EN v1.0 Size: 1716b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80074e80(int param_1,int *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80075534
 * EN v1.0 Address: 0x80075534
 * EN v1.0 Size: 716b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80075534(int x1, int y1, int x2, int y2, u8* color)
{
    extern void fn_8000FB20(void);
    extern Mtx lbl_803974E0;
    extern f32 lbl_803DFB5C;
    extern void GXSetZMode();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(lbl_803974E0, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DDC98 != 0 || lbl_803DDC94 != 7 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DDC98 = 0;
        lbl_803DDC94 = 7;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    color[3] = (u8)(((s32)color[3] * (s32)lbl_803DC2D9) >> 8);
    GXSetTevKColor(0, *(GXColor*)color);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevOrder(0, 0xFF, 0xFF, 4);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1 << 2;
    GXWGFifo.s16 = y1 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2 << 2;
    GXWGFifo.s16 = y1 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2 << 2;
    GXWGFifo.s16 = y2 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1 << 2;
    GXWGFifo.s16 = y2 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    fn_8000FB20();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80075800
 * EN v1.0 Address: 0x80075800
 * EN v1.0 Size: 920b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80075800(u8* color, f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, f32 x4, f32 y4)
{
    extern void fn_8000FB20(void);
    extern Mtx lbl_803974E0;
    extern f32 lbl_803DFBAC;
    extern f32 lbl_803DFB5C;
    extern void GXSetZMode();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    f32 scale = lbl_803DFBAC;
    f32 fx1 = scale * x1;
    f32 fy1 = scale * y1;
    f32 fx2 = scale * x2;
    f32 fy2 = scale * y2;
    f32 fx3 = scale * x3;
    f32 fy3 = scale * y3;
    f32 fx4 = scale * x4;
    f32 fy4 = scale * y4;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(lbl_803974E0, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DDC98 != 0 || lbl_803DDC94 != 7 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DDC98 = 0;
        lbl_803DDC94 = 7;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    color[3] = (u8)(((s32)color[3] * (s32)lbl_803DC2D9) >> 8);
    GXSetTevKColor(0, *(GXColor*)color);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevOrder(0, 0xFF, 0xFF, 4);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s32)fx1;
    GXWGFifo.s16 = (s32)fy1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s32)fx2;
    GXWGFifo.s16 = (s32)fy2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s32)fx3;
    GXWGFifo.s16 = (s32)fy3;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s32)fx4;
    GXWGFifo.s16 = (s32)fy4;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    fn_8000FB20();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80075b98
 * EN v1.0 Address: 0x80075B98
 * EN v1.0 Size: 832b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80075B98(u8* color, f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3)
{
    extern void fn_8000FB20(void);
    extern Mtx lbl_803974E0;
    extern f32 lbl_803DFBAC;
    extern f32 lbl_803DFB5C;
    extern void GXSetZMode();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    f32 scale = lbl_803DFBAC;
    f32 fx1 = scale * x1;
    f32 fy1 = scale * y1;
    f32 fx2 = scale * x2;
    f32 fy2 = scale * y2;
    f32 fx3 = scale * x3;
    f32 fy3 = scale * y3;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(lbl_803974E0, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DDC98 != 0 || lbl_803DDC94 != 7 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DDC98 = 0;
        lbl_803DDC94 = 7;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    color[3] = (u8)(((s32)color[3] * (s32)lbl_803DC2D9) >> 8);
    GXSetTevKColor(0, *(GXColor*)color);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevOrder(0, 0xFF, 0xFF, 4);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXBegin(GX_TRIANGLES, GX_VTXFMT1, 3);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s32)fx1;
    GXWGFifo.s16 = (s32)fy1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s32)fx2;
    GXWGFifo.s16 = (s32)fy2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s32)fx3;
    GXWGFifo.s16 = (s32)fy3;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DFB5C;
    GXWGFifo.f32 = lbl_803DFB5C;

    fn_8000FB20();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80075ed8
 * EN v1.0 Address: 0x80075ED8
 * EN v1.0 Size: 304b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80075ED8(int x1, int y1, int x2, int y2, int z, f32 u1, f32 v1, f32 u2, f32 v2)
{
    extern void fn_8000FB20(void);
    extern Mtx lbl_803974E0;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(lbl_803974E0, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v2;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v2;

    fn_8000FB20();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80076008
 * EN v1.0 Address: 0x80076008
 * EN v1.0 Size: 316b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80076008(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2)
{
    extern void fn_8000FB20(void);
    extern Mtx lbl_803974E0;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(lbl_803974E0, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v2;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v2;

    fn_8000FB20();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80076144
 * EN v1.0 Address: 0x80076144
 * EN v1.0 Size: 1352b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80076144(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7,int param_8,int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007668c
 * EN v1.0 Address: 0x8007668C
 * EN v1.0 Size: 780b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007668c(double param_1,double param_2,int param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80076998
 * EN v1.0 Address: 0x80076998
 * EN v1.0 Size: 1372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80076998(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7,uint param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80076ef4
 * EN v1.0 Address: 0x80076EF4
 * EN v1.0 Size: 1060b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80076ef4(undefined4 param_1,undefined4 param_2,int param_3,undefined4 *param_4,uint param_5
                 ,uint param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80077318
 * EN v1.0 Address: 0x80077318
 * EN v1.0 Size: 1128b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80077318(double param_1,double param_2,int param_3,uint param_4,uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80077780
 * EN v1.0 Address: 0x80077780
 * EN v1.0 Size: 648b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80077780(f32* obj, u32* colorPtr, Mtx mtx)
{
    extern void fn_8004C460(int, int);
    extern GXColor lbl_803DC308;
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    Mtx tmp;

    GXSetTevSwapModeTable(1, 3, 0, 3, 0);
    PSMTXConcat((float(*)[4])obj, mtx, tmp);
    GXLoadTexMtxImm(tmp, 0x1E, 1);
    GXSetTexCoordGen2(0, 1, 0, 0x1E, 0, 0x7D);
    fn_8004C460(*(int*)(obj + 0x18), 0);
    GXSetTevKColor(0, *(GXColor*)colorPtr);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevColor(2, lbl_803DC308);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevAlphaIn(0, 2, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 1);
    GXSetTevColorOp(0, 0, 0, 0, 0, 1);
    GXSetTevAlphaOp(0, 0xE, 0, 0, 1, 0);
    GXSetBlendMode(1, 4, 5, 5);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    if ((u32)lbl_803DDC98 != 1 || lbl_803DDC94 != 3 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DDC98 = 1;
        lbl_803DDC94 = 3;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    if ((u32)lbl_803DDC91 != 1 || lbl_803DDC99 == 0) {
        GXSetZCompLoc(1);
        lbl_803DDC91 = 1;
        lbl_803DDC99 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80077a08
 * EN v1.0 Address: 0x80077A08
 * EN v1.0 Size: 588b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80077A08(f32* obj, u32* colorPtr, Mtx mtx)
{
    extern void fn_8004C460(int, int);
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    Mtx tmp;

    PSMTXConcat((float(*)[4])obj, mtx, tmp);
    GXLoadTexMtxImm(tmp, 0x1E, 1);
    GXSetTexCoordGen2(0, 1, 0, 0x1E, 0, 0x7D);
    fn_8004C460(*(int*)(obj + 0x18), 0);
    GXSetTevKColor(0, *(GXColor*)colorPtr);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetBlendMode(1, 4, 5, 5);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    if ((u32)lbl_803DDC98 != 1 || lbl_803DDC94 != 3 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DDC98 = 1;
        lbl_803DDC94 = 3;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    if ((u32)lbl_803DDC91 != 1 || lbl_803DDC99 == 0) {
        GXSetZCompLoc(1);
        lbl_803DDC91 = 1;
        lbl_803DDC99 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80077c54
 * EN v1.0 Address: 0x80077C54
 * EN v1.0 Size: 1056b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80077c54(double param_1,float *param_2,int param_3,float *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80078074
 * EN v1.0 Address: 0x80078074
 * EN v1.0 Size: 2120b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80078074(undefined4 param_1,undefined4 param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800788bc
 * EN v1.0 Address: 0x800788BC
 * EN v1.0 Size: 204b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800788BC(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    if ((u32)lbl_803DDC98 != 1 || lbl_803DDC94 != 3 ||
        (u32)lbl_803DDC92 != 1 || lbl_803DDC9A == 0) {
        GXSetZMode(1, 3, 1);
        lbl_803DDC98 = 1;
        lbl_803DDC94 = 3;
        lbl_803DDC92 = 1;
        lbl_803DDC9A = 1;
    }
    GXSetBlendMode(0, 1, 0, 5);
    if ((u32)lbl_803DDC91 != 1 || lbl_803DDC99 == 0) {
        GXSetZCompLoc(1);
        lbl_803DDC91 = 1;
        lbl_803DDC99 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80078988
 * EN v1.0 Address: 0x80078988
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078988(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    if ((u32)lbl_803DDC98 != 1 || lbl_803DDC94 != 3 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DDC98 = 1;
        lbl_803DDC94 = 3;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    GXSetBlendMode(0, 1, 0, 5);
    if ((u32)lbl_803DDC91 != 1 || lbl_803DDC99 == 0) {
        GXSetZCompLoc(1);
        lbl_803DDC91 = 1;
        lbl_803DDC99 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80078a58
 * EN v1.0 Address: 0x80078A58
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078A58(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    if ((u32)lbl_803DDC98 != 1 || lbl_803DDC94 != 3 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DDC98 = 1;
        lbl_803DDC94 = 3;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    GXSetBlendMode(1, 4, 1, 5);
    if ((u32)lbl_803DDC91 != 1 || lbl_803DDC99 == 0) {
        GXSetZCompLoc(1);
        lbl_803DDC91 = 1;
        lbl_803DDC99 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80078b28
 * EN v1.0 Address: 0x80078B28
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078B28(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    if ((u32)lbl_803DDC98 != 0 || lbl_803DDC94 != 7 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DDC98 = 0;
        lbl_803DDC94 = 7;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    GXSetBlendMode(1, 4, 1, 5);
    if ((u32)lbl_803DDC91 != 1 || lbl_803DDC99 == 0) {
        GXSetZCompLoc(1);
        lbl_803DDC91 = 1;
        lbl_803DDC99 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80078bf8
 * EN v1.0 Address: 0x80078BF8
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078BF8(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    if ((u32)lbl_803DDC98 != 0 || lbl_803DDC94 != 7 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DDC98 = 0;
        lbl_803DDC94 = 7;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DDC91 != 1 || lbl_803DDC99 == 0) {
        GXSetZCompLoc(1);
        lbl_803DDC91 = 1;
        lbl_803DDC99 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80078cc8
 * EN v1.0 Address: 0x80078CC8
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078CC8(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    if ((u32)lbl_803DDC98 != 1 || lbl_803DDC94 != 3 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DDC98 = 1;
        lbl_803DDC94 = 3;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DDC91 != 1 || lbl_803DDC99 == 0) {
        GXSetZCompLoc(1);
        lbl_803DDC91 = 1;
        lbl_803DDC99 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80078d98
 * EN v1.0 Address: 0x80078D98
 * EN v1.0 Size: 480b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078D98(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DDC92;
    extern int lbl_803DDC94;
    extern u8 lbl_803DDC98;
    GXSetCullMode(0);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 8, 2, 0xF);
    GXSetTevAlphaIn(0, 7, 7, 7, 4);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    if ((u32)lbl_803DDC98 != 0 || lbl_803DDC94 != 7 ||
        (u32)lbl_803DDC92 != 0 || lbl_803DDC9A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DDC98 = 0;
        lbl_803DDC94 = 7;
        lbl_803DDC92 = 0;
        lbl_803DDC9A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DDC91 != 1 || lbl_803DDC99 == 0) {
        GXSetZCompLoc(1);
        lbl_803DDC91 = 1;
        lbl_803DDC99 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80078f78
 * EN v1.0 Address: 0x80078F78
 * EN v1.0 Size: 212b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078F78(void)
{
    GXSetTevOrder(lbl_803DDCB0, 0xFF, 0xFF, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0, 10, 0xF);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 0, 5, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDC89 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007904c
 * EN v1.0 Address: 0x8007904C
 * EN v1.0 Size: 212b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_8007904C(void)
{
    GXSetTevOrder(lbl_803DDCB0, 0xFF, 0xFF, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 10, 4, 0xF);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 5, 2, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDC89 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80079120
 * EN v1.0 Address: 0x80079120
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80079120(void)
{
    GXSetTevOrder(lbl_803DDCB0, lbl_803DDCAC, lbl_803DDCA8, 0xFF);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 4, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 2, 4, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(lbl_803DDCAC, 1, 4, 0x3C, 0, 0x7D);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDCAC += 1;
    lbl_803DDC8A += 1;
    lbl_803DDCA8 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80079228
 * EN v1.0 Address: 0x80079228
 * EN v1.0 Size: 212b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80079228(void)
{
    GXSetTevOrder(lbl_803DDCB0, 0xFF, 0xFF, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0xF, 0xF, 4);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 7, 7, 2);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDC89 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800792fc
 * EN v1.0 Address: 0x800792FC
 * EN v1.0 Size: 212b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800792FC(void)
{
    GXSetTevOrder(lbl_803DDCB0, 0xFF, 0xFF, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0xF, 0xF, 10);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 7, 7, 5);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDC89 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800793d0
 * EN v1.0 Address: 0x800793D0
 * EN v1.0 Size: 212b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800793D0(void)
{
    GXSetTevOrder(lbl_803DDCB0, 0xFF, 0xFF, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0, 4, 0xF);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 0, 2, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDC89 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800794a4
 * EN v1.0 Address: 0x800794A4
 * EN v1.0 Size: 440b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800794A4(void)
{
    GXSetTevOrder(lbl_803DDCB0, lbl_803DDCAC, lbl_803DDCA8, 0xFF);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 7, 7, 4);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDCA8 += 1;
    GXSetTevOrder(lbl_803DDCB0, lbl_803DDCAC, lbl_803DDCA8, 0xFF);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0, 8, 3, 0xF);
    GXSetTevAlphaIn(lbl_803DDCB0, 0, 4, 1, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(lbl_803DDCAC, 1, 4, 0x3C, 0, 0x7D);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDCAC += 1;
    lbl_803DDC8A += 1;
    lbl_803DDCA8 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007965c
 * EN v1.0 Address: 0x8007965C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_8007965C(void)
{
    GXSetTevOrder(lbl_803DDCB0, lbl_803DDCAC, lbl_803DDCA8, 0xFF);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0xF, 0xF, 4);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 4, 2, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(lbl_803DDCAC, 1, 4, 0x3C, 0, 0x7D);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDCA8 += 1;
    lbl_803DDCAC += 1;
    lbl_803DDC8A += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80079764
 * EN v1.0 Address: 0x80079764
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80079764(void)
{
    GXSetTevOrder(lbl_803DDCB0, lbl_803DDCAC, lbl_803DDCA8, 0xFF);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 8, 4, 0xF);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 4, 2, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(lbl_803DDCAC, 1, 4, 0x3C, 0, 0x7D);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDCA8 += 1;
    lbl_803DDCAC += 1;
    lbl_803DDC8A += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007986c
 * EN v1.0 Address: 0x8007986C
 * EN v1.0 Size: 276b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_8007986C(void)
{
    GXSetTevOrder(lbl_803DDCB0, lbl_803DDCAC, lbl_803DDCA8, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 8, 10, 0xF);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 4, 5, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTexCoordGen2(lbl_803DDCAC, 1, 4, 0x3C, 0, 0x7D);
    lbl_803DDCB0 += 1;
    lbl_803DDC8B += 1;
    lbl_803DDCA8 += 1;
    lbl_803DDCAC += 1;
    lbl_803DDC8A += 1;
    lbl_803DDC89 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80079980
 * EN v1.0 Address: 0x80079980
 * EN v1.0 Size: 444b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80079980(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80079b3c
 * EN v1.0 Address: 0x80079B3C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80079B3C(void)
{
    lbl_803DDC88 = 0;
    lbl_803DDC89 = 0;
    lbl_803DDC8A = 0;
    lbl_803DDC8B = 0;
    lbl_803DDCB0 = 0;
    lbl_803DDCAC = 0;
    lbl_803DDCA8 = 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80079b60
 * EN v1.0 Address: 0x80079B60
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80079B60(u8 r, u8 g, u8 b, u8 a)
{
    GXColor c;
    c.r = r;
    c.g = g;
    c.b = b;
    c.a = a;
    GXSetTevColor(GX_TEVREG1, c);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80079ba0
 * EN v1.0 Address: 0x80079BA0
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80079BA0(u8 r, u8 g, u8 b, u8 a)
{
    GXColor c;
    c.r = r;
    c.g = g;
    c.b = b;
    c.a = a;
    GXSetTevColor(GX_TEVREG0, c);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80079be0
 * EN v1.0 Address: 0x80079BE0
 * EN v1.0 Size: 1024b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80079be0(double param_1,double param_2,byte param_3,char param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80079fe0
 * EN v1.0 Address: 0x80079FE0
 * EN v1.0 Size: 2232b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80079fe0(double param_1,double param_2,double param_3,undefined param_4,undefined4 param_5,
                 undefined param_6,undefined param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007a898
 * EN v1.0 Address: 0x8007A898
 * EN v1.0 Size: 1524b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007a898(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007ae8c
 * EN v1.0 Address: 0x8007AE8C
 * EN v1.0 Size: 780b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007ae8c(double param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007b198
 * EN v1.0 Address: 0x8007B198
 * EN v1.0 Size: 3440b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007b198(double param_1,double param_2,double param_3,char param_4,char param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007bf08
 * EN v1.0 Address: 0x8007BF08
 * EN v1.0 Size: 1604b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007bf08(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007c54c
 * EN v1.0 Address: 0x8007C54C
 * EN v1.0 Size: 660b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_8007C54C(u8 flag)
{
    extern f32 lbl_803DFB5C;
    extern f32 lbl_803DFB78;
    extern void fn_8006C86C(int);
    f32 mtx[6];

    fn_8006C86C(1);
    GXSetTexCoordGen2(1, 0, 0, 0x24, 0, 0x7D);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    mtx[0] = lbl_803DFB5C;
    mtx[1] = lbl_803DFB78;
    mtx[2] = lbl_803DFB5C;
    mtx[3] = lbl_803DFB5C;
    mtx[4] = lbl_803DFB5C;
    mtx[5] = lbl_803DFB78;
    GXSetIndTexOrder(0, 0, 0);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (void*)mtx, -2);
    GXSetTevIndirect(1, 0, 0, 7, 1, 0, 0, 0, 0, 1);
    GXSetNumIndStages(1);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0xFF, 0xFF, 4);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xA);
    GXSetTevAlphaIn(0, 7, 7, 7, 5);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    if (flag != 0) {
        GXSetTevColorIn(1, 8, 0xF, 0xF, 0);
    } else {
        GXSetTevColorIn(1, 0xF, 8, 0, 0xF);
    }
    GXSetTevOrder(1, 1, 1, 8);
    GXSetTevAlphaIn(1, 7, 5, 0, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8007c7e0
 * EN v1.0 Address: 0x8007C7E0
 * EN v1.0 Size: 1168b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007c7e0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007cc70
 * EN v1.0 Address: 0x8007CC70
 * EN v1.0 Size: 1160b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007cc70(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007d0f8
 * EN v1.0 Address: 0x8007D0F8
 * EN v1.0 Size: 1780b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007d0f8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007d7ec
 * EN v1.0 Address: 0x8007D7EC
 * EN v1.0 Size: 108b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* EN v1.0 Size: 108b - 77% match. MWCC recomputes &lbl_80397420 for
 * each PSMTXConcat call; target caches it once in r31 (callee-save)
 * and reuses across both calls. Register-allocator preference — not
 * crackable without inline asm. */
void fn_8007D7EC(void)
{
    Mtx* mats = &lbl_80397420;
    Mtx tmp;
    PSMTXConcat(mats[3], mats[0], tmp);
    GXLoadTexMtxImm(tmp, 0x1E, GX_MTX3x4);
    PSMTXConcat(mats[2], mats[0], tmp);
    GXLoadTexMtxImm(tmp, 0x24, GX_MTX3x4);
}

/*
 * --INFO--
 *
 * Function: OSReport
 * EN v1.0 Address: 0x8007D858
 * EN v1.0 Size: 80b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Retail ships a locally-defined empty OSReport that disables debug
 * output. MWCC generates a varargs prologue saving r3-r10 and, if
 * cr1 indicates FP args, f1-f8 — exactly what the empty body emits.
 */
void OSReport(const char* msg, ...)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007d858
 * EN v1.0 Address: 0x8007D858
 * EN v1.0 Size: 80b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007d858(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007d8a8
 * EN v1.0 Address: 0x8007D8A8
 * EN v1.0 Size: 564b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8007d8a8(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8007dadc
 * EN v1.0 Address: 0x8007DADC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_8007DADC(u32 param_1)
{
    u8 v = (u8)param_1;
    lbl_803DDCD9 = v;
    if (v != 0) {
        return;
    }
    lbl_803DDCCC = 0;
    lbl_803DDCC8 = 0;
    lbl_803DDCD4 = 0;
    lbl_803DDCD0 = 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007db04
 * EN v1.0 Address: 0x8007DB04
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007DB04(void)
{
    lbl_803DC360 = 0xd;
}

/*
 * --INFO--
 *
 * Function: FUN_8007db10
 * EN v1.0 Address: 0x8007DB10
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
s32 fn_8007DB10(void)
{
    return lbl_803DC360;
}

/*
 * --INFO--
 *
 * Function: FUN_8007db18
 * EN v1.0 Address: 0x8007DB18
 * EN v1.0 Size: 392b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void fn_8007E7A0(int);
extern int fn_8007ED98(int, int, int, int, int, void*);
extern void fn_8007E328(int);
extern void fn_8007E928(void);
extern void fn_8007E99C(void);
extern void fn_8007E9D0(void);
extern u8 lbl_803DDCD8;

#pragma scheduling off
int fn_8007DB18(void)
{
    extern void* fn_80023D8C();
    extern s32 CARDMount();
    extern s32 CARDCheck();
    extern s32 CARDDelete();
    extern void CARDUnmount();
    extern void fn_800238C4();
    extern void fn_80080084();
    extern void* lbl_803DDCC0;
    extern const char* lbl_803DC364;
    extern s32 lbl_803DC360;
    int res;

    lbl_803DDCD8 = 0;

    do {
        if (fn_8007DF88(0) == 0) {
            return 0;
        }
        lbl_803DDCC0 = fn_80023D8C(0xA000, -1, 0);
        if (lbl_803DDCC0 == 0) {
            lbl_803DC360 = 8;
            return 0;
        }
        lbl_803DC360 = 0;
        res = CARDMount(0, lbl_803DDCC0, (void*)fn_80080084);
        if (res == 0 || res == -6) {
            if (res == -6) {
                res = CARDCheck(0);
            }
        }
        if (res == 0) {
            res = CARDDelete(0, lbl_803DC364);
        }
        CARDUnmount(0);
        fn_800238C4(lbl_803DDCC0);
        lbl_803DDCC0 = 0;

        switch (res + 13) {
            case 11: lbl_803DC360 = 1; break;
            case 10:
                if (lbl_803DC360 != 3) lbl_803DC360 = 2;
                break;
            case 0:  lbl_803DC360 = 6; break;
            case 8:  lbl_803DC360 = 4; break;
            case 13:
                lbl_803DC360 = 13;
                return 1;
        }
        fn_8007E328(0);
    } while (lbl_803DDCD8 != 0);
    return 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007dca0
 * EN v1.0 Address: 0x8007DCA0
 * EN v1.0 Size: 156b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int fn_8007DCA0(int a, int b, int c)
{
    int ret;
    lbl_803DDCD8 = 0;
    fn_8007E7A0(1);
    do {
        ret = fn_8007ED98(0, a, 0, b, c, fn_8007E928);
        fn_8007E328(0);
        if (lbl_803DDCD8 != 0) {
            fn_8007E7A0(1);
        }
    } while (lbl_803DDCD8 != 0);
    return ret;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007dd3c
 * EN v1.0 Address: 0x8007DD3C
 * EN v1.0 Size: 156b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int fn_8007DD3C(int a)
{
    int ret;
    lbl_803DDCD8 = 0;
    fn_8007E7A0(0);
    do {
        ret = fn_8007ED98(1, 0, 0, a, 0, fn_8007E99C);
        fn_8007E328(1);
        if (lbl_803DDCD8 != 0) {
            fn_8007E7A0(0);
        }
    } while (lbl_803DDCD8 != 0);
    return ret;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007ddd8
 * EN v1.0 Address: 0x8007DDD8
 * EN v1.0 Size: 168b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int fn_8007DDD8(int a, int b)
{
    int ret;
    lbl_803DDCD8 = 0;
    fn_8007E7A0(0);
    do {
        ret = fn_8007ED98(1, a, 0, b, 0, fn_8007E9D0);
        fn_8007E328(0);
        if (lbl_803DDCD8 != 0) {
            fn_8007E7A0(0);
        }
    } while (lbl_803DDCD8 != 0);
    return ret;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007de80
 * EN v1.0 Address: 0x8007DE80
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
int fn_8007DE80(u8 retry)
{
    extern int fn_8007FAC8(int);
    extern void CARDClose(void*);
    extern void CARDUnmount(s32);
    extern void fn_800238C4(void*);
    extern u8 lbl_80397560[];
    extern void* lbl_803DDCC0;
    extern u8 lbl_803DDCDA;
    extern s32 lbl_803DC360;
    int ret;

    if (retry != 0) {
        lbl_803DDCD8 = 0;
        fn_8007E7A0(2);
    }
    do {
        ret = fn_8007FAC8(0);
        if (ret != 0) {
            if (lbl_803DDCDA != 0) {
                lbl_803DDCDA = 0;
                CARDClose(lbl_80397560);
            }
            CARDUnmount(0);
            fn_800238C4(lbl_803DDCC0);
            lbl_803DDCC0 = 0;
            lbl_803DC360 = 13;
            if (ret == 2) {
                ret = fn_8007ED98(0, 0, 0, 0, 0, 0);
            }
        }
        if (retry != 0) {
            fn_8007E328(0);
        }
        if (lbl_803DDCD8 != 0) {
            fn_8007E7A0(2);
        }
    } while (lbl_803DDCD8 != 0 && retry != 0);
    return ret;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8007df88
 * EN v1.0 Address: 0x8007DF88
 * EN v1.0 Size: 228b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
int fn_8007DF88(u8 retry)
{
    extern s32 CARDProbeEx(s32 chan, s32* memSize, s32* sectorSize);
    extern s32 lbl_803DC360;
    s32 memSize;
    s32 sectorSize;
    s32 res;

    if (retry != 0) {
        lbl_803DDCD8 = 0;
    }
    do {
        res = -1;
        while (res == -1) {
            res = CARDProbeEx(0, &memSize, &sectorSize);
        }
        if (res == 0) {
            if (sectorSize == 0x2000) {
                lbl_803DC360 = 13;
                return 1;
            }
            lbl_803DC360 = 7;
        } else if (res == -3) {
            lbl_803DC360 = 2;
        } else if (res == -2) {
            lbl_803DC360 = 1;
        } else {
            lbl_803DC360 = 0;
        }
        if (retry != 0) {
            fn_8007E328(0);
        }
    } while (lbl_803DDCD8 != 0 && retry != 0);
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8007e06c
 * EN v1.0 Address: 0x8007E06C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007E06C(void)
{
    CARDInit();
}

/*
 * --INFO--
 *
 * Function: FUN_8007e08c
 * EN v1.0 Address: 0x8007E08C
 * EN v1.0 Size: 668b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_8007E08C(u32* buttons, u32* texts, u32* count)
{
    extern u8 lbl_803DDCD9;
    extern s32 lbl_803DC360;
    if (lbl_803DDCD9 != 0 && (lbl_803DC360 == 7 || lbl_803DC360 == 9)) {
        lbl_803DC360 = 11;
    }
    switch (lbl_803DC360) {
        case 0:
            *count = 0;
            lbl_803DC360 = 13;
            return;
        case 1:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x325;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 2:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x51A;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 3:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x51A;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 4:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x329;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 5:
            buttons[0] = 1;
            buttons[1] = 2;
            buttons[2] = 0;
            texts[0] = 0x51F;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            texts[3] = 0x326;
            *count = 3;
            return;
        case 6:
            buttons[0] = 1;
            buttons[1] = 2;
            buttons[2] = 0;
            texts[0] = 0x51E;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            texts[3] = 0x326;
            *count = 3;
            return;
        case 7:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x51C;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 8:
            *count = 0;
            return;
        case 9:
            buttons[0] = 1;
            buttons[1] = 2;
            buttons[2] = 3;
            texts[0] = 0x32A;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            texts[3] = 0x520;
            *count = 3;
            return;
        case 10:
            buttons[0] = 2;
            buttons[1] = 4;
            texts[0] = 0x497;
            texts[1] = 0x51B;
            texts[2] = 0x522;
            *count = 2;
            return;
        case 11:
        case 12:
            buttons[0] = 1;
            buttons[1] = 2;
            texts[0] = 0x521;
            texts[1] = 0x51D;
            texts[2] = 0x51B;
            *count = 2;
            return;
        case 13:
        default:
            *count = 0;
            lbl_803DC360 = 13;
            return;
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8007e328
 * EN v1.0 Address: 0x8007E328
 * EN v1.0 Size: 1144b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007e328(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}
