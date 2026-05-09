#include "ghidra_import.h"
#include "dolphin/card.h"
#include "dolphin/gx.h"
#include "dolphin/mtx.h"
#include "track/intersect.h"

extern Mtx lbl_803967C0;
extern Mtx lbl_80396820;
extern Mtx lbl_80396850;
extern f32 lbl_803DFB10;
extern f32 sqrtf(f32 x);

extern undefined4 ABS();
extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern undefined4 FUN_8000693c();
extern undefined4 FUN_80006944();
extern undefined4 FUN_80006974();
extern undefined4 FUN_80006988();
extern undefined4 FUN_80006994();
extern ushort FUN_80006998();
extern ushort FUN_800069a0();
extern undefined4 FUN_800069d4();
extern double FUN_800069d8();
extern double FUN_800069e4();
extern undefined4 FUN_80006bb8();
extern undefined4 FUN_80006bc8();
extern uint FUN_80006c00();
extern undefined4 FUN_80006c1c();
extern undefined4 FUN_80006c64();
extern undefined4 FUN_80006c78();
extern void* FUN_80017470();
extern undefined8 FUN_80017484();
extern int FUN_800174a0();
extern undefined4 FUN_800174b8();
extern uint FUN_80017690();
extern undefined4 FUN_800176a8();
extern undefined4 FUN_800176b4();
extern int FUN_800176d0();
extern double FUN_800176f4();
extern uint FUN_80017760();
extern undefined4 FUN_80017810();
extern undefined8 FUN_80017814();
extern undefined4 FUN_80017830();
extern int FUN_8001792c();
extern undefined4 FUN_8001794c();
extern undefined4 FUN_80017970();
extern uint FUN_80017a98();
extern uint FUN_8003ba68();
extern undefined4 FUN_80045c4c();
extern undefined4 FUN_8004600c();
extern char FUN_80048094();
extern undefined4 FUN_800480a0();
extern undefined4 FUN_800480b4();
extern undefined4 FUN_8004812c();
extern uint FUN_80053078();
extern undefined4 FUN_8005398c();
extern int FUN_800632e0();
extern undefined4 FUN_8006af44();
extern void newshadows_getShadowDirectionTexture(int *textureOut);
extern void newshadows_getSoftShadowTexture(int *textureOut);
extern void newshadows_getShadowRampTexture(int *textureOut);
extern void newshadows_getShadowDiskTexture(int *textureOut);
extern undefined4 FUN_8006b024();
extern void newshadows_getShadowNoiseTexture(int *textureOut);
extern undefined4 FUN_8006b0bc();
extern undefined4 FUN_8006b0e8();
extern void newshadows_bindShadowRenderTexture(int textureSlot);
extern int newshadows_getShadowRenderTexture(void);
extern int FUN_8006b188();
extern void newshadows_flushShadowRenderTargets(void);
extern void newshadows_getShadowNoiseScroll(float *xOffsetOut,float *yOffsetOut);
extern undefined8 FUN_8007e77c();
extern undefined4 FUN_8007ea1c();
extern undefined4 FUN_8007ea90();
extern undefined4 FUN_8007eac4();
extern undefined8 FUN_8007f00c();
extern int FUN_8007f350();
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
extern undefined4 FUN_80293f84();
extern undefined4 FUN_80293f88();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 SQRT();

extern undefined4 DAT_80392a44;
extern undefined4 DAT_80392a48;
extern undefined4 DAT_80392a4c;
extern undefined4 DAT_80392a4e;
extern undefined4 DAT_80392a4f;
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
extern u8 lbl_803965E0[0xF0];
extern undefined4 DAT_80397244;
extern u8 lbl_803966D0[0xF0];
extern undefined4 DAT_80397332;
extern undefined4 DAT_80397338;
extern undefined4 lbl_803DB65C;
extern undefined4 lbl_803DB660;
extern undefined4 lbl_803DB668;
extern undefined4 lbl_803DB6D4;
/* Narrow-typed aliases for sbss/sdata state vars touched by the small
 * helpers below. */
extern u8 lbl_803DC2D9;
extern volatile s32 lbl_803DB700;
extern u32 lbl_803DD004;
extern u8 lbl_803DD019;
extern u8 lbl_803DD01A;
extern GXColor lbl_803DDC9C;
extern u8 lbl_803DDC88;
extern u8 lbl_803DD009;
extern u8 lbl_803DD00A;
extern u8 lbl_803DD00B;
extern u32 lbl_803DDCB0;
extern u32 lbl_803DDCAC;
extern u32 lbl_803DDCA8;
extern u8 lbl_803DD059;
extern u32 lbl_803DDCC8;
extern u32 lbl_803DD04C;
extern u32 lbl_803DDCD0;
extern u32 lbl_803DD054;
extern u8 lbl_803DD011;
extern f32 lbl_803DDCA0;
extern f32 lbl_803DDCA4;
extern f32 lbl_803DD034;
extern f32 lbl_803DDCB8;
extern undefined4* lbl_803DCA58;
extern undefined4* pDll_expgfx;
extern undefined4* lbl_803DCA98;
extern undefined4 lbl_803DCFF0;
extern undefined4 lbl_803DCFF8;
extern u8 lbl_803DCFF9;
extern u16 lbl_803DD000;
extern u16 lbl_803DD002;
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
 * Function: fn_8006EF38
 * EN v1.0 Address: 0x8006EF38
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8006F0B4
 * EN v1.1 Size: 1224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8006EF38(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7)
{
}

/*
 * --INFO--
 *
 * Function: fn_8006F388
 * EN v1.0 Address: 0x8006EF3C
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x8006F504
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void* fn_8006F388(u32 i)
{
    extern u8 lbl_8030E8B0[];
    u8* base = lbl_8030E8B0;
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
 * Function: FUN_8006efb4
 * EN v1.0 Address: 0x8006EFB4
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8006F57C
 * EN v1.1 Size: 256b
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
void fn_8006F400(f32 step)
{
    int i;
    u8* a;
    u8* b;
    extern u8 lbl_80392DE0[];
    extern u8 lbl_80391DE0[];

    a = lbl_80392DE0;
    b = lbl_80391DE0;
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
 * Function: fn_8006F500
 * EN v1.0 Address: 0x8006F09C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8006F67C
 * EN v1.1 Size: 1104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8006F500(void)
{
}

/*
 * --INFO--
 *
 * Function: fn_8006F950
 * EN v1.0 Address: 0x8006F0A0
 * EN v1.0 Size: 1016b
 * EN v1.1 Address: 0x8006FACC
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8006F950(undefined4 param_1,undefined4 param_2,undefined param_3,uint param_4)
{
  extern undefined4 lbl_80391DE0;
  extern undefined4 lbl_80391DC0;
  extern undefined4 lbl_80392DE0;
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
    lbl_803DCFF0 = *(byte *)((int)psVar8 + 0xad);
  }
  else if (psVar8[0x23] == 0x416) {
    lbl_803DCFF0 = 3;
  }
  iVar9 = FUN_800632e0((double)*(float *)(psVar8 + 6),(double)*(float *)(psVar8 + 8),
                       (double)*(float *)(psVar8 + 10),psVar8,&fStack_58,afStack_54,0);
  if (iVar9 == 0) {
    if ((param_4 & 0xff) == 1) {
      iVar9 = (uint)lbl_803DCFF8 * 0x10;
      *(float *)(&lbl_80391DE0 + iVar9) = *pfVar10;
      *(float *)(&DAT_80392a44 + iVar9) = FLOAT_803dfabc + pfVar10[1];
      *(float *)(&DAT_80392a48 + iVar9) = pfVar10[2];
      *(short *)(&DAT_80392a4c + iVar9) = *psVar8;
      (&DAT_80392a4e)[iVar9] = 0xff;
      (&DAT_80392a4f)[iVar9] = param_3;
      uVar7 = lbl_803DCFF8 + 1;
      lbl_803DCFF8 = (byte)uVar7;
      if (0xff < (uVar7 & 0xff)) {
        lbl_803DCFF8 = 0;
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
    dVar11 = (double)(float)(&lbl_80391DC0)[lbl_803DCFF0];
    FUN_80247edc(dVar11,&local_3c,&local_3c);
    FUN_80247edc(dVar11,&local_48,&local_48);
    fVar1 = *pfVar10;
    fVar2 = pfVar10[1];
    fVar3 = pfVar10[2];
    fVar4 = fVar1 - local_3c;
    uVar7 = (uint)lbl_803DCFF9;
    iVar9 = uVar7 * 0x38;
    (&lbl_80392DE0)[uVar7 * 0xe] = fVar4 - local_48;
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
    lbl_803DCFF9 = (byte)(uVar7 + 1);
    if (0xff < (uVar7 + 1 & 0xff)) {
      lbl_803DCFF9 = 0;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006f498
 * EN v1.0 Address: 0x8006F498
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x8006FD7C
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_8006FC00(int param_1)
{
    int i;
    u8* a;
    u8* b;
    extern u8 lbl_80392DE0[];
    extern u8 lbl_80391DE0[];
    extern u8 lbl_803DDC78;
    extern u8 lbl_803DCFFA;

    lbl_803DCFFA = (u8)param_1;
    if (param_1 != 0) {
        return;
    }
    a = lbl_80392DE0;
    b = lbl_80391DE0;
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
    lbl_803DCFF9 = 0;
    lbl_803DDC78 = 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8006f564
 * EN v1.0 Address: 0x8006F564
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x8006FE48
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_8006FCCC(void)
{
    extern u8 lbl_80391DC0[];
    extern f32 lbl_803DFADC, lbl_803DFAE0, lbl_803DFAE4;
    extern u32 fn_80054ED0(int);
    extern u32 lbl_803DDC74;
    extern u8 lbl_803DDC78, lbl_803DCFF9, lbl_803DCFFA;
    int i;
    u8* base = lbl_80391DC0;
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
    lbl_803DCFFA = 0;
    lbl_803DCFF9 = 0;
    lbl_803DDC78 = 0;
    lbl_803DDC74 = 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8006FDF8
 * EN v1.0 Address: 0x8006F690
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x8006FF74
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
int fn_8006FDF8(int x, int y, int id)
{
    bool ok;
    u8* row;
    int* found;
    int i;
    u32 n;

    ok = false;
    if (x >= 0 && x < 0x280 && y >= 0 && y < 0x1E0) {
        ok = true;
    }
    if (ok) {
        if (x < 0x10) x = 0x10;
        if (y < 6) y = 6;
        n = (u32)lbl_803DD000;
        if (n < 0x14) {
            u8* slot = (u8*)&lbl_803966D0 + n * 0xC;
            *(u16*)(slot + 0x0) = (u16)x;
            *(u16*)(slot + 0x2) = (u16)y;
            *(int*)(slot + 0x8) = id;
            lbl_803DD000++;
        }
        i = 0;
        row = (u8*)&lbl_803965E0;
        n = (u32)lbl_803DD002;
        while (n != 0) {
            if (id == *(int*)(row + 0x8)) {
                found = (int*)((u8*)&lbl_803965E0 + i * 0xC);
                return found[1];
            }
            row += 0xC;
            i++;
            n--;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8006f764
 * EN v1.0 Address: 0x8006F764
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80070050
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
uint fn_8006FED4(void)
{
    u32 v = lbl_803DD004;
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
 * Function: FUN_8006f788
 * EN v1.0 Address: 0x8006F788
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80070074
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8006FEF8(u32 param_1)
{
    lbl_803DD004 = param_1;
}

/*
 * --INFO--
 *
 * Function: FUN_8006f790
 * EN v1.0 Address: 0x8006F790
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8007007C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8006FF00(void)
{
    lbl_803DD004 = 0;
}

/*
 * --INFO--
 *
 * Function: fn_8006FF0C
 * EN v1.0 Address: 0x8006F79C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80070088
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8006FF0C(double param_1,double param_2,double param_3,double param_4,double param_5,
                 float *param_6,short *param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8006f7a0
 * EN v1.0 Address: 0x8006F7A0
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x80070320
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_800701A4(f32* x, f32* y, f32* z)
{
    f32 scale;
    f32 len;

    len = sqrtf(*z * *z + (*x * *x + *y * *y));
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
 * Function: FUN_8006f830
 * EN v1.0 Address: 0x8006F830
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x800703B0
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803DEE98;
extern f32 lbl_803DEE9C;

/* EN v1.0 Size: 132b - 74% match. 4x4 identity fill. Remaining diff:
 * target uses 'li r0, N; cmpw r4, r0' per column, mine uses 'cmpwi
 * r4, N' — MWCC always folds the integer literal into the compare
 * immediate form. The +4 extra li instructions explain the 116 vs
 * 132 byte discrepancy. Not crackable without materializing the
 * comparison indices via a global/volatile, which would break other
 * matches. */
#pragma scheduling off
#pragma peephole off
void fn_80070234(f32* param_1)
{
    int i = 0, j;
    f32 zero, one;
    one = lbl_803DEE98;
    zero = lbl_803DEE9C;
    for (; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            if (i == j) param_1[j] = one; else param_1[j] = zero;
        }
        param_1 += 4;
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8006f8a4
 * EN v1.0 Address: 0x8006F8A4
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x80070434
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void gxSetPeControl_ZCompLoc_(u32 param_1)
{
    extern void GXSetZCompLoc();
    if ((u32)lbl_803DD011 != (param_1 & 0xff) || lbl_803DD019 == 0) {
        GXSetZCompLoc(param_1);
        lbl_803DD011 = (u8)param_1;
        lbl_803DD019 = 1;
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8006f8fc
 * EN v1.0 Address: 0x8006F8FC
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x8007048C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void gxSetZMode_(u32 param_1, int param_2, u32 param_3)
{
    extern void GXSetZMode();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
    extern u8 lbl_803DD01A;

    if ((u32)lbl_803DD018 != (param_1 & 0xff) ||
        lbl_803DD014 != param_2 ||
        (u32)lbl_803DD012 != (param_3 & 0xff) ||
        lbl_803DD01A == 0) {
        GXSetZMode(param_1, param_2, param_3);
        lbl_803DD018 = (u8)param_1;
        lbl_803DD014 = param_2;
        lbl_803DD012 = (u8)param_3;
        lbl_803DD01A = 1;
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8006f998
 * EN v1.0 Address: 0x8006F998
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80070528
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_800703AC(void)
{
    lbl_803DD01A = 0;
    lbl_803DD019 = 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8006f9a8
 * EN v1.0 Address: 0x8006F9A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80070538
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_800703BC(u8 param_1)
{
    lbl_803DC2D9 = param_1;
}

/*
 * --INFO--
 *
 * Function: FUN_8006f9b0
 * EN v1.0 Address: 0x8006F9B0
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80070540
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800703C4(void)
{
    GXColor c = lbl_803DDC9C;
    GXSetFog(GX_FOG_PERSP_EXP, lbl_803DDCA4, lbl_803DDCA0, lbl_803DDCB8, lbl_803DD034, c);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8006f9f0
 * EN v1.0 Address: 0x8006F9F0
 * EN v1.0 Size: 220b
 * EN v1.1 Address: 0x80070580
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma scheduling off
#pragma peephole off
void fn_80070404(f32 a, f32 b)
{
    extern f32 Camera_GetNearPlane(void);
    extern f32 Camera_GetFarPlane(void);
    extern f32 lbl_803DEED8;
    extern f32 lbl_803DEEDC;
    extern f32 gSynthFadeMask;
    extern f32 lbl_803DD020, lbl_803DD024, lbl_803DD034, lbl_803DD038;
    extern GXColor lbl_803DD01C;
    f32 xc, yc, x, y, range;
    GXColor c;

    lbl_803DD038 = Camera_GetNearPlane();
    lbl_803DD034 = Camera_GetFarPlane();

    x = lbl_803DEED8 * a;
    y = lbl_803DEED8 * b;

    xc = lbl_803DEEDC;
    if (x >= lbl_803DEEDC) {
        xc = x;
        if (x > gSynthFadeMask) {
            xc = gSynthFadeMask;
        }
    }
    yc = lbl_803DEEDC;
    if (y >= lbl_803DEEDC) {
        yc = y;
        if (y > gSynthFadeMask) {
            yc = gSynthFadeMask;
        }
    }

    range = lbl_803DD034 - lbl_803DD038;
    lbl_803DD024 = xc * range + lbl_803DD038;
    lbl_803DD020 = yc * range + lbl_803DD038;
    c = lbl_803DD01C;
    GXSetFog(GX_FOG_PERSP_EXP, lbl_803DD024, lbl_803DD020, lbl_803DD038, lbl_803DD034, c);
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8006facc
 * EN v1.0 Address: 0x8006FACC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80070658
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800704DC(u8* param_1)
{
    param_1[0] = lbl_803DDC9C.r;
    param_1[1] = lbl_803DDC9C.g;
    param_1[2] = lbl_803DDC9C.b;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8006faec
 * EN v1.0 Address: 0x8006FAEC
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80070678
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800704FC(u8 param_1, u8 param_2, u8 param_3)
{
    lbl_803DDC9C.r = param_1;
    lbl_803DDC9C.g = param_2;
    lbl_803DDC9C.b = param_3;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_80070510
 * EN v1.0 Address: 0x8006FB00
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007068C
 * EN v1.1 Size: 2500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80070510(void* obj_a, void** obj_b, int param_3)
{
    extern f32 lbl_803DEEE4;
    extern u32 lbl_803DB6F4, lbl_803DB6F8;
    extern u32 lbl_803DD01C;
    extern u8 lbl_803DB678;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern Mtx lbl_80396850;
    extern Mtx lbl_80396820;
    extern f32 lbl_8030EAA0[3][3];
    extern void* gSHthorntailAnimationInterface;
    extern int ObjModel_GetRenderOp(void* model, int slot);
    extern int* fn_8004C250(void* op, int slot);
    extern void* textureIdxToPtr(int idx);
    extern void selectTexture(void* tex, int slot);
    extern void selectReflectionTexture(int);
    extern void GXInitTexObj();
    extern void fn_8006CABC(void* a, void* b);
    extern int fn_8004C248(void);
    extern void* (*ObjModel_GetPostRenderCallback(void* obj_b))();
    extern int fn_8003BB74(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    void* renderOp;
    void* tex2;
    void* model;
    int handle1;
    f32 buf10[3];
    GXColor tev_color;
    GXColor k_color;
    Mtx scaleMtx;
    f32 fA, fB;
    int wrapBit;
    void (*pcb)(void*, void**, int);

    model = obj_b[0];
    renderOp = (void*)ObjModel_GetRenderOp(model, param_3);
    handle1 = *fn_8004C250(renderOp, 0);
    selectTexture(textureIdxToPtr(handle1), 0);
    selectReflectionTexture(1);
    tex2 = textureIdxToPtr(*(int*)((u8*)renderOp + 0x34));
    wrapBit = (((u8*)tex2)[0x1d] - ((u8*)tex2)[0x1c] > 0) ? 1 : 0;
    GXInitTexObj((void*)((u8*)tex2 + 0x20), (u8*)tex2 + 0x60,
                 *(u16*)((u8*)tex2 + 0xa), *(u16*)((u8*)tex2 + 0xc),
                 ((u8*)tex2)[0x16], 1, 1, wrapBit);
    selectTexture(tex2, 2);
    GXLoadTexMtxImm(lbl_80396850, 0x52, 0);
    GXSetTexCoordGen2(0, 0, 0, 0, 0, 0x52);
    GXLoadTexMtxImm(lbl_80396820, 0x55, 0);
    GXSetTexCoordGen2(1, 0, 0, 0, 0, 0x55);
    fn_8006CABC(&fA, &fB);
    PSMTXScale(scaleMtx, lbl_803DEEE4, lbl_803DEEE4, lbl_803DEEE4);
    scaleMtx[1][2] = -fA;
    GXLoadTexMtxImm(scaleMtx, 0x21, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x21, 0, 0x7d);
    GXSetTexCoordGen2(3, 1, 4, 0x21, 0, 0x7d);

    if (fn_8004C248() != 0) {
        *(u32*)&k_color = lbl_803DD01C;
        ((u8*)&lbl_803DB6F4)[0] = ((u8*)&lbl_803DD01C)[0];
        ((u8*)&lbl_803DB6F4)[1] = ((u8*)&lbl_803DD01C)[1];
        ((u8*)&lbl_803DB6F4)[2] = ((u8*)&lbl_803DD01C)[2];
        ((u8*)&lbl_803DB6F4)[3] = 0x80;
    } else {
        (*(void(**)(u8*, u8*, u8*, f32*, f32*, f32*))(*(int*)gSHthorntailAnimationInterface + 0x40))(
            (u8*)&lbl_803DB6F4,
            (u8*)&lbl_803DB6F4 + 1,
            (u8*)&lbl_803DB6F4 + 2,
            buf10, buf10, buf10);
        ((u8*)&lbl_803DB6F4)[0] = (u8)(((s8)((u8*)&lbl_803DB6F4)[0]) >> 3);
        ((u8*)&lbl_803DB6F4)[1] = (u8)(((s8)((u8*)&lbl_803DB6F4)[1]) >> 3);
        ((u8*)&lbl_803DB6F4)[2] = (u8)(((s8)((u8*)&lbl_803DB6F4)[2]) >> 3);
        ((u8*)&lbl_803DB6F4)[3] = lbl_803DB678;
    }
    *(u32*)&tev_color = lbl_803DB6F4;
    GXSetTevColor(3, tev_color);
    *(u32*)&k_color = lbl_803DB6F8;
    GXSetTevKColor(0, k_color);
    GXSetTevKColorSel(1, 0xC);
    GXSetIndTexOrder(0, 2, 2);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, lbl_8030EAA0, -1);
    GXSetIndTexMtx(2, lbl_8030EAA0, -2);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevIndirect(1, 0, 0, 7, 2, 0, 0, 0, 0, 0);
    GXSetTevOrder(0, 0, 1, 0xff);
    GXSetTevColorIn(0, 6, 0xf, 0xf, 8);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    if (fn_8004C248() != 0) {
        GXSetTevColorOp(0, 0, 0, 3, 1, 0);
    } else {
        GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    }
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetTevOrder(1, 1, 1, 0xff);
    GXSetTevColorIn(1, 0, 8, 0xe, 0xf);
    GXSetTevAlphaIn(1, 7, 7, 7, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    GXSetTevDirect(2);
    GXSetTevOrder(2, 3, 0, 4);
    GXSetTevColorIn(2, 0, 8, 9, 0xf);
    GXSetTevAlphaIn(2, 7, 7, 7, 5);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumIndStages(1);
    GXSetNumChans(1);
    GXSetNumTexGens(4);
    GXSetNumTevStages(3);

    pcb = (void(*)(void*, void**, int))ObjModel_GetPostRenderCallback(obj_b);
    if (pcb != 0) {
        pcb(obj_a, obj_b, param_3);
    } else {
        u8 zCompLoc = 1;
        u32 flags2;
        u32 modelFlags;
        if (((u8*)obj_a)[0x37] >= 0xFF
            && (*(u32*)((u8*)renderOp + 0x3c) & 0x40000000) == 0
            && ((u8*)renderOp)[0xc] >= 0xFF) {
            /* opaque path */
            flags2 = *(u32*)((u8*)renderOp + 0x3c);
            modelFlags = *(u32*)((u8*)renderOp + 0x3c);
            if ((*(u16*)((u8*)model + 2) & 0x400) != 0) {
                /* alpha-test path */
                int a = fn_8003BB74();
                int b = fn_8003BB74();
                GXSetBlendMode(0, 1, 0, 5);
                if ((modelFlags & 0x400) != 0) {
                    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 3 ||
                        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                        GXSetZMode(0, 3, 0);
                        lbl_803DD018 = 0;
                        lbl_803DD014 = 3;
                        lbl_803DD012 = 0;
                        lbl_803DD01A = 1;
                    }
                } else {
                    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
                        (u32)lbl_803DD012 != 1 || lbl_803DD01A == 0) {
                        GXSetZMode(1, 3, 1);
                        lbl_803DD018 = 1;
                        lbl_803DD014 = 3;
                        lbl_803DD012 = 1;
                        lbl_803DD01A = 1;
                    }
                }
                GXSetAlphaCompare(4, 0xC0, 0, 4, 0xC0);
            } else {
                GXSetBlendMode(0, 1, 0, 5);
                if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(1, 3, 0);
                    lbl_803DD018 = 1;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            }
        } else {
            /* translucent path */
            if ((*(u16*)((u8*)model + 2) & 0x400) != 0) {
                GXSetBlendMode(1, 4, 5, 5);
                if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(1, 3, 1);
                    lbl_803DD018 = 1;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            } else {
                if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(0, 3, 0);
                    lbl_803DD018 = 0;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
                GXSetAlphaCompare(7, 0, 0, 7, 0);
            }
        }
        if ((*(u32*)((u8*)renderOp + 0x3c) & 0x400) != 0) {
            zCompLoc = 0;
        }
        if (lbl_803DD011 != zCompLoc || lbl_803DD019 == 0) {
            GXSetZCompLoc(zCompLoc);
            lbl_803DD011 = zCompLoc;
            lbl_803DD019 = 1;
        }
        if ((*(u32*)((u8*)renderOp + 0x3c) & 0x10) != 0) {
            GXSetCullMode(2);
        } else {
            GXSetCullMode(0);
        }
    }
}

/*
 * --INFO--
 *
 * Function: fn_80070ED4
 * EN v1.0 Address: 0x8006FB04
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80071050
 * EN v1.1 Size: 2344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80070ED4(u8 alpha)
{
    extern f32 lbl_803DEEE4, lbl_803DEEEC, lbl_803DEEF0;
    extern f32 gSynthVoiceSlots;
    extern u32 lbl_803DB6E0, lbl_803DB6E4, lbl_803DB6E8, lbl_803DB6EC, lbl_803DB6F0;
    extern f32 lbl_8030EA70[3][3];
    extern f32 lbl_8030EA88[3][3];
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern void fn_8006CABC(f32* a, f32* b);
    extern void getTextureFn_8006c5e4(int* out);
    extern void updateReflectionTextures(void);
    extern void selectReflectionTexture(int);
    extern void selectTexture(int handle, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_30;
    Mtx mtx_60;
    int handle;
    f32 fA;
    f32 fB;
    GXColor temp_color;

    fn_8006CABC(&fA, &fB);
    getTextureFn_8006c5e4(&handle);
    updateReflectionTextures();
    selectReflectionTexture(0);
    selectTexture(handle, 1);
    ((u8*)&lbl_803DB6E4)[3] = alpha;
    *(u32*)&temp_color = lbl_803DB6E4;
    GXSetTevKColor(0, temp_color);
    *(u32*)&temp_color = lbl_803DB6E8;
    GXSetTevKColor(1, temp_color);
    *(u32*)&temp_color = lbl_803DB6EC;
    GXSetTevKColor(2, temp_color);
    *(u32*)&temp_color = lbl_803DB6F0;
    GXSetTevKColor(3, temp_color);

    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);

    PSMTXScale(mtx_60, gSynthVoiceSlots, gSynthVoiceSlots, lbl_803DEEE4);
    mtx_60[1][3] = -fA;
    GXLoadTexMtxImm(mtx_60, 0x1e, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x1e, 0, 0x7d);

    PSMTXScale(mtx_60, lbl_803DEEEC, lbl_803DEEEC, lbl_803DEEE4);
    PSMTXRotRad(mtx_30, 'z', lbl_803DEEF0);
    PSMTXConcat(mtx_30, mtx_60, mtx_60);
    mtx_60[0][3] = fB;
    mtx_60[1][3] = fB;
    GXLoadTexMtxImm(mtx_60, 0x21, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x21, 0, 0x7d);

    /* TEV stage 0 */
    GXSetTevOrder(0, 0xFF, 0xFF, 0xFF);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    /* IndTex 0 */
    GXSetIndTexOrder(0, 1, 1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, lbl_8030EA70, -3);
    GXSetTevIndirect(1, 0, 0, 7, 1, 6, 6, 0, 0, 0);

    GXSetIndTexOrder(1, 2, 1);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetIndTexMtx(2, lbl_8030EA88, -3);
    GXSetTevIndirect(2, 1, 0, 7, 2, 0, 0, 0, 0, 1);

    /* Stage 1 */
    GXSetTevOrder(1, 0xFF, 0xFF, 8);
    GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(1, 7, 7, 7, 5);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    /* Stage 2 */
    GXSetTevOrder(2, 0, 0, 8);
    GXSetTevColorIn(2, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(2, 0, 7, 7, 5);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 3, 1, 0);

    /* Stage 3 */
    GXSetTevKColorSel(3, 0xC);
    GXSetTevKAlphaSel(3, 0x4);
    GXSetTevDirect(3);
    GXSetTevOrder(3, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(3, 0xF, 0xE, 0, 0xF);
    GXSetTevAlphaIn(3, 6, 7, 7, 0);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevColorOp(3, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(3, 1, 0, 1, 1, 1);

    /* Stage 4 */
    GXSetTevKColorSel(4, 0xD);
    GXSetTevKAlphaSel(4, 0x4);
    GXSetTevDirect(4);
    GXSetTevOrder(4, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(4, 0xE, 0xF, 0, 2);
    GXSetTevAlphaIn(4, 0, 7, 7, 6);
    GXSetTevSwapMode(4, 0, 0);
    GXSetTevColorOp(4, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(4, 1, 0, 1, 1, 2);

    /* Stage 5 */
    GXSetTevKColorSel(5, 0xE);
    GXSetTevDirect(5);
    GXSetTevOrder(5, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(5, 0xF, 0xE, 0, 0xF);
    GXSetTevAlphaIn(5, 1, 7, 7, 2);
    GXSetTevSwapMode(5, 0, 0);
    GXSetTevColorOp(5, 0, 0, 0, 1, 2);
    GXSetTevAlphaOp(5, 0, 0, 0, 1, 0);

    /* Stage 6 */
    GXSetTevKColorSel(6, 0xF);
    GXSetTevKAlphaSel(6, 0x4);
    *(u32*)&temp_color = lbl_803DB6E0;
    GXSetTevColor(3, temp_color);
    GXSetTevOrder(6, 0xFF, 0xFF, 0xFF);
    GXSetTevDirect(6);
    GXSetTevColorIn(6, 0xE, 0xF, 0, 4);
    GXSetTevAlphaIn(6, 7, 7, 7, 0);
    GXSetTevSwapMode(6, 0, 0);
    GXSetTevColorOp(6, 0, 0, 0, 1, 2);
    GXSetTevAlphaOp(6, 0, 0, 0, 1, 0);

    /* Stage 7 */
    GXSetTevKAlphaSel(7, 0x1C);
    GXSetTevDirect(7);
    GXSetTevOrder(7, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(7, 4, 2, 1, 0xF);
    GXSetTevAlphaIn(7, 7, 7, 7, 6);
    GXSetTevSwapMode(7, 0, 0);
    GXSetTevColorOp(7, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(7, 0, 0, 0, 1, 0);

    GXSetNumTexGens(3);
    GXSetNumIndStages(2);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTevStages(8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(0x3C);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(0);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_800717FC
 * EN v1.0 Address: 0x8006FB08
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80071978
 * EN v1.1 Size: 1368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_800717FC(void)
{
    extern u32 lbl_803DB6D0, lbl_803DB6D4, lbl_803DB6D8, lbl_803DB6DC;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern void updateReflectionTextures(void);
    extern void selectReflectionTexture(int);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    GXColor temp;

    updateReflectionTextures();
    selectReflectionTexture(0);
    GXSetTevSwapModeTable(0, 1, 2, 0, 3);
    GXSetTevSwapModeTable(1, 0, 0, 0, 3);
    GXSetTevSwapModeTable(2, 1, 1, 1, 3);
    GXSetTevSwapModeTable(3, 2, 2, 2, 3);

    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);

    *(u32*)&temp = lbl_803DB6D0;
    GXSetTevKColor(0, temp);
    *(u32*)&temp = lbl_803DB6D4;
    GXSetTevKColor(1, temp);
    *(u32*)&temp = lbl_803DB6D8;
    GXSetTevKColor(2, temp);
    *(u32*)&temp = lbl_803DB6DC;
    GXSetTevColor(1, temp);

    GXSetNumTexGens(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTevStages(4);

    GXSetTevKColorSel(0, 0xC);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 8, 0xe, 2);
    GXSetTevAlphaIn(0, 7, 7, 7, 1);
    GXSetTevSwapMode(0, 0, 1);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevKColorSel(1, 0xD);
    GXSetTevKAlphaSel(1, 0x1D);
    GXSetTevDirect(1);
    GXSetTevOrder(1, 0, 0, 0xff);
    GXSetTevColorIn(1, 0xf, 8, 0xe, 0);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 2);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 3);

    GXSetTevKColorSel(2, 0xE);
    GXSetTevDirect(2);
    GXSetTevOrder(2, 0, 0, 0xff);
    GXSetTevColorIn(2, 0xf, 8, 0xe, 0);
    GXSetTevAlphaIn(2, 7, 7, 7, 0);
    GXSetTevSwapMode(2, 0, 3);
    GXSetTevColorOp(2, 0, 0, 3, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);

    GXSetTevDirect(3);
    GXSetTevOrder(3, 0, 0, 0xff);
    GXSetTevColorIn(3, 0, 0xf, 0xf, 8);
    GXSetTevAlphaIn(3, 7, 7, 7, 0);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevColorOp(3, 1, 0, 2, 1, 0);
    GXSetTevAlphaOp(3, 0, 0, 0, 1, 0);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(0, 1, 0, 5);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(0x3C);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
    GXSetTevSwapModeTable(0, 0, 1, 2, 3);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_80071D54
 * EN v1.0 Address: 0x8006FB0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80071ED0
 * EN v1.1 Size: 1372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80071D54(u8* mod)
{
    extern u32 lbl_803DEEC8, lbl_803DEECC, lbl_803DEED0, lbl_803DEED4;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern void updateReflectionTextures(void);
    extern void selectReflectionTexture(int);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    GXColor c0, c1, c2, c3;

    *(u32*)&c0 = lbl_803DEEC8;
    *(u32*)&c1 = lbl_803DEECC;
    *(u32*)&c2 = lbl_803DEED0;
    *(u32*)&c3 = lbl_803DEED4;
    {
        int s0 = mod[0] >> 3;
        int s1 = mod[1] >> 3;
        int s2 = mod[2] >> 3;
        c0.r = (u8)(c0.r + s0);
        c0.g = (u8)(c0.g + s1);
        c0.b = (u8)(c0.b + s2);
        c1.r = (u8)(c1.r + s0);
        c1.g = (u8)(c1.g + s1);
        c1.b = (u8)(c1.b + s2);
        c2.r = (u8)(c2.r + s0);
        c2.g = (u8)(c2.g + s1);
        c2.b = (u8)(c2.b + s2);
    }

    updateReflectionTextures();
    selectReflectionTexture(0);
    GXSetTevSwapModeTable(1, 0, 0, 0, 3);
    GXSetTevSwapModeTable(2, 1, 1, 1, 3);
    GXSetTevSwapModeTable(3, 2, 2, 2, 3);

    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);

    GXSetTevKColor(0, c0);
    GXSetTevKColor(1, c1);
    GXSetTevKColor(2, c2);
    GXSetTevColor(1, c3);

    GXSetNumTexGens(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTevStages(3);

    GXSetTevKColorSel(0, 0xC);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 8, 0xe, 2);
    GXSetTevAlphaIn(0, 7, 7, 7, 1);
    GXSetTevSwapMode(0, 0, 1);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevKColorSel(1, 0xD);
    GXSetTevKAlphaSel(1, 0x1D);
    GXSetTevDirect(1);
    GXSetTevOrder(1, 0, 0, 0xff);
    GXSetTevColorIn(1, 0xf, 8, 0xe, 0);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 2);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 3);

    GXSetTevKColorSel(2, 0xE);
    GXSetTevDirect(2);
    GXSetTevOrder(2, 0, 0, 0xff);
    GXSetTevColorIn(2, 0xf, 8, 0xe, 0);
    GXSetTevAlphaIn(2, 7, 7, 7, 0);
    GXSetTevSwapMode(2, 0, 3);
    GXSetTevColorOp(2, 0, 0, 3, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(0, 1, 0, 5);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(0x3C);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
    GXSetTevSwapModeTable(0, 0, 1, 2, 3);
}

/*
 * --INFO--
 *
 * Function: fn_800722B0
 * EN v1.0 Address: 0x8006FB10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007242C
 * EN v1.1 Size: 2892b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_800722B0(double radius, double angle, float* pos, u8* mod)
{
    extern f32 playerMapOffsetX, playerMapOffsetZ;
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 lbl_803DEF08;
    extern f32 lbl_803DEF24;
    extern f32 lbl_803DB6C4, lbl_803DB6C8, lbl_803DB6CC;
    extern f32 gSynthDelayedActionWord0, gSynthFadeMask;
    extern struct { f32 x, y; } lbl_803DEF1C;
    extern u32 lbl_803DEEB8, lbl_803DEEBC, lbl_803DEEC0, lbl_803DEEC4;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern void selectReflectionTexture(int);
    extern void getReflectionTexture2(int* out);
    extern void fn_8006C540(int* out);
    extern void fn_8006C534(int* out);
    extern void selectTexture(int handle, int slot);
    extern void Camera_ProjectWorldSphere(f32* p0, f32* p1, f32* p2, f32* p3, f32* p4, f32* p5,
                                          double x, double y, double z, double r);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_d0;
    Mtx mtx_a0;
    Mtx mtx_70;
    f32 indMtx[6];
    int handle1;
    int handle2;
    int handle3;
    f32 proj0, proj1, proj2, proj3, proj4, proj5;
    GXColor c0;
    GXColor c1;
    GXColor c2;
    GXColor c3;

    *(u32*)&c0 = lbl_803DEEB8;
    *(u32*)&c1 = lbl_803DEEBC;
    *(u32*)&c2 = lbl_803DEEC0;
    *(u32*)&c3 = lbl_803DEEC4;
    c0.r = (u8)(c0.r + (mod[0] >> 2));
    c0.g = (u8)(c0.g + (mod[1] >> 2));
    c0.b = (u8)(c0.b + (mod[2] >> 2));
    c1.r = (u8)(c1.r + (mod[0] >> 2));
    c1.g = (u8)(c1.g + (mod[1] >> 2));
    c1.b = (u8)(c1.b + (mod[2] >> 2));
    c2.r = (u8)(c2.r + (mod[0] >> 2));
    c2.g = (u8)(c2.g + (mod[1] >> 2));
    c2.b = (u8)(c2.b + (mod[2] >> 2));
    c3.r = (u8)(c3.r + (mod[0] >> 3));
    c3.g = (u8)(c3.g + (mod[1] >> 3));
    c3.b = (u8)(c3.b + (mod[2] >> 3));

    Camera_ProjectWorldSphere(&proj5, &proj4, &proj3, &proj2, &proj1, &proj0,
                              pos[0] - playerMapOffsetX, pos[1], pos[2] - playerMapOffsetZ, radius);
    proj3 = proj3 + lbl_803DEEE4;
    c0.a = (u8)(((u32)(lbl_803DEF08 * proj3) & 0x00FF0000) >> 16);

    selectReflectionTexture(0);
    getReflectionTexture2(&handle1);
    selectTexture(handle1, 1);
    fn_8006C540(&handle2);
    selectTexture(handle2, 2);

    GXSetTevSwapModeTable(1, 0, 0, 0, 3);
    GXSetTevSwapModeTable(2, 1, 1, 1, 3);
    GXSetTevSwapModeTable(3, 2, 2, 2, 3);

    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    GXSetTexCoordGen2(1, 1, 4, 0x3C, 0, 0x7D);

    /* Build cylinder matrix */
    PSMTXTrans(mtx_a0, gSynthDelayedActionWord0 * (-proj5) - gSynthDelayedActionWord0,
                       gSynthDelayedActionWord0 * proj4 - gSynthDelayedActionWord0,
                       lbl_803DEEDC);
    PSMTXScale(mtx_70, lbl_803DB6C4 / proj1, lbl_803DB6C4 / proj2, lbl_803DEEDC);
    PSMTXConcat(mtx_70, mtx_a0, mtx_d0);
    PSMTXTrans(mtx_a0, gSynthDelayedActionWord0, gSynthDelayedActionWord0, lbl_803DEEDC);
    PSMTXConcat(mtx_a0, mtx_d0, mtx_d0);
    GXLoadTexMtxImm(mtx_d0, 0x1e, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x1e, 0, 0x7d);

    /* Compute scaled radius (with rsqrt refinement when positive) */
    {
        f32 r2 = lbl_803DB6C8 / (f32)radius;
        f32 sr;
        if (r2 > lbl_803DEEDC) {
            f32 e = (f32)(1.0 / __frsqrte((double)r2));
            sr = r2 * e;
        } else {
            sr = r2;
        }
        if (sr > lbl_803DEEE4) {
            c2.a = 0xFF;
        } else {
            c2.a = (u8)(s32)(lbl_803DEF1C.y * sr);
        }
        sr = sr * gSynthFadeMask;
        if (sr > lbl_803DEEE4) sr = lbl_803DEEE4;
        c1.a = (u8)(s32)(lbl_803DEF1C.y * sr);
    }

    /* Stage K-color setup */
    GXSetTevKColor(0, c0);
    GXSetTevKColor(1, c1);
    GXSetTevKColor(2, c2);
    GXSetTevColor(1, c3);

    /* Third texture for indirect */
    fn_8006C534(&handle3);
    selectTexture(handle3, 3);

    /* Indirect tex matrix scale */
    {
        f32 ind_s = lbl_803DB6CC / (f32)radius;
        if (ind_s > gSynthDelayedActionWord0) ind_s = gSynthDelayedActionWord0;
        indMtx[0] = ind_s;
        indMtx[1] = lbl_803DEEDC;
        indMtx[2] = lbl_803DEEDC;
        indMtx[3] = lbl_803DEEDC;
        indMtx[4] = ind_s;
        indMtx[5] = lbl_803DEEDC;
    }

    /* Build indirect tex matrix */
    PSMTXTrans(mtx_a0, gSynthDelayedActionWord0 * (-proj5) - gSynthDelayedActionWord0,
                       gSynthDelayedActionWord0 * proj4 - gSynthDelayedActionWord0,
                       lbl_803DEEDC);
    PSMTXScale(mtx_70, lbl_803DEF24, lbl_803DEF24, lbl_803DEEDC);
    PSMTXRotRad(mtx_d0, 'z', angle);
    PSMTXConcat(mtx_70, mtx_a0, mtx_70);
    PSMTXConcat(mtx_d0, mtx_70, mtx_d0);
    PSMTXTrans(mtx_a0, gSynthDelayedActionWord0, gSynthDelayedActionWord0, lbl_803DEEDC);
    PSMTXConcat(mtx_a0, mtx_d0, mtx_d0);
    GXLoadTexMtxImm(mtx_d0, 0x21, 1);
    GXSetTexCoordGen2(3, 1, 4, 0x21, 0, 0x7d);

    GXSetIndTexOrder(0, 3, 3);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx, 1);

    /* Indirect for stages 2, 3, 4 */
    GXSetTevIndirect(2, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevIndirect(3, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevIndirect(4, 0, 0, 7, 1, 0, 0, 0, 0, 0);

    GXSetNumTexGens(4);
    GXSetNumIndStages(1);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTevStages(6);

    /* Stage 0 */
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 1, 1, 0xFF);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(0, 4, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 1);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 1, 0, 2, 1, 3);

    /* Stage 1 */
    GXSetTevKAlphaSel(1, 0x1C);
    GXSetTevDirect(1);
    GXSetTevOrder(1, 1, 1, 0xFF);
    GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(1, 6, 7, 7, 4);
    GXSetTevSwapMode(1, 0, 1);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 1, 0, 2, 1, 0);

    /* Stage 2 */
    GXSetTevKColorSel(2, 0x0C);
    GXSetTevOrder(2, 0, 0, 0xFF);
    GXSetTevColorIn(2, 0xF, 0x8, 0xE, 0x2);
    GXSetTevAlphaIn(2, 7, 0, 1, 7);
    GXSetTevSwapMode(2, 0, 1);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 2, 1, 0);

    /* Stage 3 */
    GXSetTevKColorSel(3, 0x0D);
    GXSetTevKAlphaSel(3, 0x1D);
    GXSetTevOrder(3, 0, 0, 0xFF);
    GXSetTevColorIn(3, 0xF, 0x8, 0xE, 0);
    GXSetTevAlphaIn(3, 7, 3, 6, 7);
    GXSetTevSwapMode(3, 0, 2);
    GXSetTevColorOp(3, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(3, 0, 0, 2, 1, 3);

    /* Stage 4 */
    GXSetTevKColorSel(4, 0x0E);
    GXSetTevOrder(4, 0, 0, 0xFF);
    GXSetTevColorIn(4, 0xF, 0x8, 0xE, 0);
    GXSetTevAlphaIn(4, 3, 7, 7, 0);
    GXSetTevSwapMode(4, 0, 3);
    GXSetTevColorOp(4, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(4, 0, 0, 2, 1, 0);

    /* Stage 5 */
    GXSetTevDirect(5);
    GXSetTevOrder(5, 2, 2, 0xFF);
    GXSetTevColorIn(5, 0xF, 0xF, 0xF, 0);
    GXSetTevAlphaIn(5, 4, 7, 0, 7);
    GXSetTevSwapMode(5, 0, 0);
    GXSetTevColorOp(5, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(5, 0, 0, 0, 1, 0);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 5, 4, 5);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(0x3C);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_80072DFC
 * EN v1.0 Address: 0x8006FB14
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80072F78
 * EN v1.1 Size: 2160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80072DFC(void* obj_a, void** obj_b, int param_3)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 lbl_803DB6B8, lbl_803DB6C0;
    extern u32 lbl_803DB6BC;
    extern f32 gSynthDelayedActionWord0;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern Mtx lbl_80396820;
    extern f32 lbl_8030EA58[3][3];
    extern int ObjModel_GetRenderOp(void* model, int slot);
    extern void* fn_8006C744(void);
    extern void selectReflectionTexture(int);
    extern void fn_8006C6A4(int);
    extern void selectTexture(void* tex, int slot);
    extern void* (*ObjModel_GetPostRenderCallback(void* obj_b))();
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_24;
    Mtx mtx_54;
    void* renderOp;
    void* tex;
    void* model;
    GXColor temp;
    void (*pcb)(void*, void**, int);
    int alpha_byte;

    model = obj_b[0];
    renderOp = (void*)ObjModel_GetRenderOp(model, param_3);
    tex = fn_8006C744();
    selectReflectionTexture(0);
    selectTexture(tex, 1);
    fn_8006C6A4(2);

    GXLoadTexMtxImm(lbl_80396820, 0x55, 0);
    GXSetTexCoordGen2(1, 0, 0, 0, 0, 0x55);

    if (model == 0 || *(u16*)((u8*)model + 0xe6) == 0) {
        PSMTXScale(mtx_54, lbl_803DB6B8, lbl_803DB6B8, lbl_803DEEDC);
        mtx_54[2][0] = lbl_803DEEE4;
        PSMTXTrans(mtx_24, gSynthDelayedActionWord0, gSynthDelayedActionWord0, lbl_803DEEDC);
        PSMTXConcat(mtx_24, mtx_54, mtx_54);
    } else {
        PSMTXScale(mtx_54, lbl_803DEEDC, lbl_803DEEDC, lbl_803DEEDC);
        mtx_54[0][3] = gSynthDelayedActionWord0;
        mtx_54[1][3] = gSynthDelayedActionWord0;
        mtx_54[2][0] = lbl_803DEEE4;
    }
    GXLoadTexMtxImm(mtx_54, 0x52, 0);
    GXSetTexCoordGen2(0, 0, 1, 0x1e, 1, 0x52);

    PSMTXScale(mtx_54, lbl_803DB6C0, lbl_803DB6C0, lbl_803DEEDC);
    mtx_54[2][0] = lbl_803DEEE4;
    GXLoadTexMtxImm(mtx_54, 0x4f, 0);
    GXSetTexCoordGen2(2, 0, 4, 0x3c, 0, 0x4f);

    GXSetIndTexOrder(0, 1, 1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, lbl_8030EA58, -1);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 8);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevDirect(1);
    GXSetTevOrder(1, 2, 2, 0xff);
    GXSetTevColorIn(1, 0, 8, 0xe, 0xf);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    GXSetNumIndStages(1);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(3);
    GXSetNumTevStages(2);

    alpha_byte = (((u8*)renderOp)[0xc] * ((u8*)obj_a)[0x37]) >> 8;
    ((u8*)&temp)[3] = (u8)alpha_byte;
    ((u8*)&temp)[0] = ((u8*)&temp)[0]; /* keep rgb */
    {
        u32 tmp_word;
        tmp_word = *(u32*)&temp;  /* sourced from 0x20 in stack */
        *(u32*)&temp = tmp_word;
    }
    GXSetTevKColor(0, temp);
    GXSetTevKAlphaSel(0, 0x1c);
    *(u32*)&temp = lbl_803DB6BC;
    GXSetTevKColor(1, temp);
    GXSetTevKColorSel(1, 0xd);

    pcb = (void(*)(void*, void**, int))ObjModel_GetPostRenderCallback(obj_b);
    if (pcb != 0) {
        pcb(obj_a, obj_b, param_3);
    } else {
        u8 zCompLoc = 1;
        u32 modelFlags;
        if (((u8*)obj_a)[0x37] >= 0xff
            && (*(u32*)((u8*)renderOp + 0x3c) & 0x40000000) == 0
            && ((u8*)renderOp)[0xc] >= 0xff) {
            modelFlags = *(u32*)((u8*)renderOp + 0x3c);
            if ((*(u16*)((u8*)model + 2) & 0x400) != 0) {
                GXSetBlendMode(0, 1, 0, 5);
                if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(0, 3, 0);
                    lbl_803DD018 = 0;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
            } else {
                GXSetBlendMode(0, 1, 0, 5);
                if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(1, 3, 0);
                    lbl_803DD018 = 1;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
            }
            GXSetAlphaCompare(7, 0, 0, 7, 0);
        } else {
            if ((*(u16*)((u8*)model + 2) & 0x400) != 0) {
                GXSetBlendMode(1, 4, 5, 5);
                if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(1, 3, 0);
                    lbl_803DD018 = 1;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
            } else {
                GXSetBlendMode(1, 4, 5, 5);
                if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(0, 3, 0);
                    lbl_803DD018 = 0;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
            }
            GXSetAlphaCompare(7, 0, 0, 7, 0);
        }
        if ((*(u32*)((u8*)renderOp + 0x3c) & 0x400) != 0) {
            zCompLoc = 0;
        }
        if (lbl_803DD011 != zCompLoc || lbl_803DD019 == 0) {
            GXSetZCompLoc(zCompLoc);
            lbl_803DD011 = zCompLoc;
            lbl_803DD019 = 1;
        }
        if ((*(u32*)((u8*)renderOp + 0x3c) & 0x10) != 0) {
            GXSetCullMode(2);
        } else {
            GXSetCullMode(0);
        }
    }
}

/*
 * --INFO--
 *
 * Function: fn_8007366C
 * EN v1.0 Address: 0x8007366C
 * EN v1.0 Size: 1088b
 * EN v1.1 Address: 0x800737E8
 * EN v1.1 Size: 1088b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Three-tex-coord-gen ind+direct TEV setup. Loads the active env-mtx
 * (lbl_80396820) for tex0, scales tex1 by hudScale through a 3x4
 * matrix from PSMTXScale, and stamps an indirect tex matrix from local
 * stack data. Two TEV stages: stage 0 K-modulates the texture by alpha,
 * stage 1 modulates by the second texture. Uses ind tex stage 0 to warp
 * tex coord 0 by tex1.
 */
#pragma peephole off
#pragma scheduling off
void fn_8007366C(u8 alpha)
{
    extern Mtx lbl_80396820;
    extern f32 lbl_803DEF28;
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern f32 lbl_803DEEE4;
    extern f32 lbl_803DEEEC;
    extern f32 lbl_803DEF30;
    extern f32 gSynthDelayedActionWord0;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern void Camera_GetViewMatrix(void);
    extern void selectReflectionTexture(int);
    extern void fn_8006CABC(f32* a, f32* b);
    extern void getTextureFn_8006c5e4(int* out);
    extern void fn_8006C5CC(int* out);
    extern void selectTexture(int handle, int slot);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    int handle1;
    int handle2;
    f32 a;
    f32 b;
    GXColor c;
    f32 ind_mtx[2][3];
    Mtx tex_mtx;
    Mtx mtx;

    Camera_GetViewMatrix();
    selectReflectionTexture(0);
    GXLoadTexMtxImm(lbl_80396820, 0x52, 0);
    GXSetTexCoordGen2(0, 0, 0, 0, 0, 0x52);
    fn_8006CABC(&a, &b);
    a = a * lbl_803DEF28;
    getTextureFn_8006c5e4(&handle1);
    selectTexture(handle1, 1);
    PSMTXScale((f32(*)[4])tex_mtx, hudScale, hudScale, hudScale);
    tex_mtx[0][3] = a;
    GXLoadTexMtxImm(tex_mtx, 0x21, 1);
    GXSetTexCoordGen2(1, 1, 0, 0x21, 0, 0x7D);
    ind_mtx[0][0] = gSynthDelayedActionWord0;
    ind_mtx[0][1] = lbl_803DEEDC;
    ind_mtx[0][2] = lbl_803DEEDC;
    ind_mtx[1][0] = lbl_803DEEDC;
    ind_mtx[1][1] = lbl_803DEEEC;
    ind_mtx[1][2] = lbl_803DEEDC;
    GXSetIndTexOrder(0, 1, 1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, ind_mtx, -3);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    mtx[0][0] = lbl_803DEF30;
    mtx[0][1] = lbl_803DEEDC;
    mtx[0][2] = lbl_803DEEDC;
    mtx[0][3] = gSynthDelayedActionWord0;
    mtx[1][0] = lbl_803DEEDC;
    mtx[1][1] = lbl_803DEF30;
    mtx[1][2] = lbl_803DEEDC;
    mtx[1][3] = gSynthDelayedActionWord0;
    mtx[2][0] = lbl_803DEEDC;
    mtx[2][1] = lbl_803DEEDC;
    mtx[2][2] = lbl_803DEEDC;
    mtx[2][3] = lbl_803DEEE4;
    GXLoadTexMtxImm(mtx, 0x55, 0);
    GXSetTexCoordGen2(2, 1, 1, 0x1E, 1, 0x55);
    fn_8006C5CC(&handle2);
    selectTexture(handle2, 2);
    c.a = alpha;
    GXSetTevKColor(0, c);
    GXSetTevKAlphaSel(1, 0x1C);
    GXSetNumIndStages(1);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(3);
    GXSetNumTevStages(2);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetTevDirect(1);
    GXSetTevOrder(1, 2, 2, 0xFF);
    GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0);
    GXSetTevAlphaIn(1, 7, 4, 6, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(2);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8006fb1c
 * EN v1.0 Address: 0x8006FB1C
 * EN v1.0 Size: 600b
 * EN v1.1 Address: 0x80073C28
 * EN v1.1 Size: 600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80073AAC(void* texture, u32* colorA, u32* colorB)
{
    extern void fn_8004C460(void*, int);
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
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
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetCullMode(2);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_80073D04
 * EN v1.0 Address: 0x8006FD74
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80073E80
 * EN v1.1 Size: 1036b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_80073D04(int param_1,int *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: fn_80074110
 * EN v1.0 Address: 0x8006FD7C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8007428C
 * EN v1.1 Size: 1032b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_80074110(int param_1,int *param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: fn_80074518
 * EN v1.0 Address: 0x8006FD84
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80074694
 * EN v1.1 Size: 2028b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80074518(void* obj_a, void** obj_b, int param_3)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 lbl_803DB6B0, lbl_803DB6B4;
    extern f32 gSynthDelayedActionWord0;
    extern f32 lbl_802C1F68[6];
    extern Mtx lbl_80396820;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern int ObjModel_GetRenderOp(void* model, int slot);
    extern int* fn_8004C250(void* op, int slot);
    extern void* textureIdxToPtr(int idx);
    extern void selectTexture(void* tex, int slot);
    extern void* (*ObjModel_GetPostRenderCallback(void* obj_b))();
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_30;
    Mtx mtx_60;
    Mtx mtx_90;
    f32 indMtx[6];
    void* renderOp;
    void* tex;
    void* model;
    GXColor temp;
    int alpha_byte;
    void (*pcb)(void*, void**, int);

    indMtx[0] = lbl_802C1F68[0];
    indMtx[1] = lbl_802C1F68[1];
    indMtx[2] = lbl_802C1F68[2];
    indMtx[3] = lbl_802C1F68[3];
    indMtx[4] = lbl_802C1F68[4];
    indMtx[5] = lbl_802C1F68[5];

    model = obj_b[0];
    renderOp = (void*)ObjModel_GetRenderOp(model, param_3);
    tex = textureIdxToPtr(*fn_8004C250(renderOp, 0));

    PSMTXScale(mtx_60, lbl_803DB6B4, lbl_803DB6B4, lbl_803DEEDC);
    mtx_60[2][3] = lbl_803DEEE4;
    GXLoadTexMtxImm(mtx_60, 0x55, 0);
    GXSetTexCoordGen2(0, 0, 1, 0x1e, 1, 0x55);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);
    GXSetNumIndStages(2);
    GXSetIndTexOrder(0, 0, 2);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx, 0);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    selectTexture(tex, 0);
    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xc);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetIndTexOrder(1, 0, 2);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetTevIndirect(1, 1, 0, 7, 1, 0, 0, 0, 0, 1);
    PSMTXScale(mtx_30, lbl_803DB6B0, lbl_803DB6B0, lbl_803DEEE4);
    PSMTXConcat(mtx_30, lbl_80396820, mtx_90);
    PSMTXTrans(mtx_30,
               gSynthDelayedActionWord0 * (lbl_803DEEE4 - lbl_803DB6B0),
               gSynthDelayedActionWord0 * (lbl_803DEEE4 - lbl_803DB6B0),
               lbl_803DEEDC);
    PSMTXConcat(mtx_30, mtx_90, mtx_90);
    GXLoadTexMtxImm(mtx_90, 0x52, 0);
    GXSetTexCoordGen2(1, 0, 0, 0, 1, 0x52);

    alpha_byte = (((u8*)renderOp)[0xc] * ((u8*)obj_a)[0x37]) >> 8;
    ((u8*)&temp)[3] = (u8)alpha_byte;
    GXSetTevKColor(0, temp);
    GXSetTevKAlphaSel(1, 0x1c);
    GXSetTevOrder(1, 1, 0, 4);
    GXSetTevColorIn(1, 0xf, 0xa, 8, 0xf);
    GXSetTevAlphaIn(1, 7, 7, 7, 6);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    pcb = (void(*)(void*, void**, int))ObjModel_GetPostRenderCallback(obj_b);
    if (pcb != 0) {
        pcb(obj_a, obj_b, param_3);
    } else {
        u8 zCompLoc = 1;
        u32 modelFlags;
        if (((u8*)obj_a)[0x37] >= 0xff
            && (*(u32*)((u8*)renderOp + 0x3c) & 0x40000000) == 0
            && ((u8*)renderOp)[0xc] >= 0xff) {
            modelFlags = *(u32*)((u8*)renderOp + 0x3c);
            if ((*(u16*)((u8*)model + 2) & 0x400) != 0) {
                GXSetBlendMode(0, 1, 0, 5);
                if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(0, 3, 0);
                    lbl_803DD018 = 0;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
            } else {
                GXSetBlendMode(0, 1, 0, 5);
                if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(1, 3, 0);
                    lbl_803DD018 = 1;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
            }
            GXSetAlphaCompare(7, 0, 0, 7, 0);
        } else {
            if ((*(u16*)((u8*)model + 2) & 0x400) != 0) {
                GXSetBlendMode(1, 4, 5, 5);
                if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(1, 3, 0);
                    lbl_803DD018 = 1;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
            } else {
                GXSetBlendMode(1, 4, 5, 5);
                if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 3 ||
                    (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
                    GXSetZMode(0, 3, 0);
                    lbl_803DD018 = 0;
                    lbl_803DD014 = 3;
                    lbl_803DD012 = 0;
                    lbl_803DD01A = 1;
                }
            }
            GXSetAlphaCompare(7, 0, 0, 7, 0);
        }
        if ((*(u32*)((u8*)renderOp + 0x3c) & 0x400) != 0) {
            zCompLoc = 0;
        }
        if (lbl_803DD011 != zCompLoc || lbl_803DD019 == 0) {
            GXSetZCompLoc(zCompLoc);
            lbl_803DD011 = zCompLoc;
            lbl_803DD019 = 1;
        }
        if ((*(u32*)((u8*)renderOp + 0x3c) & 0x10) != 0) {
            GXSetCullMode(2);
        } else {
            GXSetCullMode(0);
        }
    }
}

/*
 * --INFO--
 *
 * Function: fn_80074D04
 * EN v1.0 Address: 0x8006FD88
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80074E80
 * EN v1.1 Size: 1716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 fn_80074D04(int handle, void* model)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4, lbl_803DEEF0;
    extern f32 lbl_803DEF3C, lbl_803DEF40, lbl_803DEF44, lbl_803DEF48;
    extern f32 lbl_803DB6AC;
    extern f32 hudScale;
    extern f32 gSynthDelayedActionWord0;
    extern Mtx lbl_80396820;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern f32* Camera_GetViewMatrix(void);
    extern f32* ObjModel_GetJointMatrix(void* model, int joint);
    extern void selectReflectionTexture(int);
    extern void fn_8006CABC(f32* a, f32* b);
    extern void getTextureFn_8006c5e4(int* out);
    extern void fn_8006C5CC(int* out);
    extern void selectTexture(int handle, int slot);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_8c;
    Mtx mtx_bc;
    Mtx mtx_ec;
    Mtx mtx_5c;
    f32 indMtx_44[6];
    f32 indMtx_2c[6];
    f32 buf_8c_2[12];
    int handle1, handle2;
    f32 f1, f2;
    f32 f31_val;
    GXColor temp;
    f32* viewMtx;

    viewMtx = Camera_GetViewMatrix();
    if (model != 0) {
        f32* jm = ObjModel_GetJointMatrix(model, 0);
        f32 px, py, pz, dist;
        PSMTXConcat((f32(*)[4])viewMtx, (f32(*)[4])jm, mtx_8c);
        px = mtx_8c[0][3];
        py = mtx_8c[1][3];
        pz = mtx_8c[2][3];
        dist = px*px + py*py + pz*pz;
        if (dist > lbl_803DEEDC) {
            f32 e = (f32)(1.0 / __frsqrte((double)dist));
            dist = dist * e;
        }
        f31_val = lbl_803DEF3C / dist;
        if (f31_val > lbl_803DEEE4) f31_val = lbl_803DEEE4;
    } else {
        f31_val = lbl_803DEEE4;
    }

    selectReflectionTexture(0);
    GXLoadTexMtxImm(lbl_80396820, 0x52, 0);
    GXSetTexCoordGen2(0, 0, 0, 0, 0, 0x52);
    fn_8006CABC(&f1, &f2);
    f1 *= hudScale;
    f2 *= hudScale;
    getTextureFn_8006c5e4(&handle1);
    selectTexture(handle1, 1);

    PSMTXScale(mtx_ec, hudScale, hudScale, hudScale);
    mtx_ec[2][2] = f1;
    GXLoadTexMtxImm(mtx_ec, 0x21, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x21, 0, 0x7d);

    /* indMtx_44 (6 floats) — first ind matrix */
    {
        f32 v = gSynthDelayedActionWord0 * f31_val;
        indMtx_44[0] = v;
        indMtx_44[1] = lbl_803DEEDC;
        indMtx_44[2] = lbl_803DEEDC;
        indMtx_44[3] = lbl_803DEEDC;
        indMtx_44[4] = v;
        indMtx_44[5] = lbl_803DEEDC;
    }
    GXSetIndTexOrder(0, 1, 1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx_44, -4);
    GXSetTevIndirect(0, 0, 0, 7, 1, 6, 6, 0, 0, 0);

    PSMTXScale(mtx_bc, lbl_803DEF40, lbl_803DEF40, lbl_803DEF40);
    PSMTXRotRad(mtx_5c, 'z', lbl_803DEEF0);
    PSMTXConcat(mtx_5c, mtx_bc, mtx_bc);
    mtx_bc[2][2] = f2;
    mtx_bc[3][2] = f2;
    GXLoadTexMtxImm(mtx_bc, 0x24, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x24, 0, 0x7d);

    /* indMtx_2c — second ind matrix */
    {
        f32 v44 = lbl_803DEF44 * f31_val;
        f32 v48 = lbl_803DEF48 * f31_val;
        indMtx_2c[0] = v44;
        indMtx_2c[1] = v44;
        indMtx_2c[2] = lbl_803DEEDC;
        indMtx_2c[3] = v48;
        indMtx_2c[4] = v44;
        indMtx_2c[5] = lbl_803DEEDC;
    }
    GXSetIndTexOrder(1, 2, 1);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetIndTexMtx(2, (f32(*)[3])indMtx_2c, -4);
    GXSetTevIndirect(1, 1, 1, 7, 2, 0, 0, 0, 0, 1);

    /* buf_8c_2 — third tex matrix at slot 0x55 */
    buf_8c_2[0] = lbl_803DB6AC;
    buf_8c_2[1] = lbl_803DEEDC;
    buf_8c_2[2] = lbl_803DEEDC;
    buf_8c_2[3] = gSynthDelayedActionWord0;
    buf_8c_2[4] = lbl_803DEEDC;
    buf_8c_2[5] = lbl_803DB6AC;
    buf_8c_2[6] = lbl_803DEEDC;
    buf_8c_2[7] = gSynthDelayedActionWord0;
    buf_8c_2[8] = lbl_803DEEDC;
    buf_8c_2[9] = lbl_803DEEDC;
    buf_8c_2[10] = lbl_803DEEDC;
    buf_8c_2[11] = lbl_803DEEE4;
    GXLoadTexMtxImm((f32(*)[4])buf_8c_2, 0x55, 0);
    GXSetTexCoordGen2(3, 0, 1, 0x1e, 0, 0x55);

    fn_8006C5CC(&handle2);
    selectTexture(handle2, 2);

    GXSetNumIndStages(2);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(4);
    GXSetNumTevStages(3);

    GXSetTevOrder(0, 0, 0, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xf);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevOrder(1, 0, 0, 0xff);
    GXSetTevColorIn(1, 0xf, 0xf, 0xf, 8);
    GXSetTevAlphaIn(1, 7, 7, 7, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    /* Set TEV K-color from handle (alpha) */
    ((u8*)&temp)[3] = ((u8*)(int)handle)[0x37];
    GXSetTevKColor(0, temp);
    GXSetTevKAlphaSel(2, 0x1c);
    GXSetTevDirect(2);
    GXSetTevOrder(2, 3, 2, 0xff);
    GXSetTevColorIn(2, 0xf, 0xf, 0xf, 0);
    GXSetTevAlphaIn(2, 7, 4, 6, 7);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);

    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetBlendMode(1, 4, 5, 5);
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8006fd90
 * EN v1.0 Address: 0x8006FD90
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x80075534
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void hudDrawRect(int x1, int y1, int x2, int y2, u8* color)
{
    extern void Camera_RebuildProjectionMatrix(void);
    extern Mtx hudMatrix;
    extern f32 lbl_803DEEDC;
    extern void GXSetZMode();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
    extern u8 lbl_803DB679;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    color[3] = (u8)(((s32)color[3] * (s32)lbl_803DB679) >> 8);
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
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2 << 2;
    GXWGFifo.s16 = y1 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2 << 2;
    GXWGFifo.s16 = y2 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1 << 2;
    GXWGFifo.s16 = y2 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8007005c
 * EN v1.0 Address: 0x8007005C
 * EN v1.0 Size: 952b
 * EN v1.1 Address: 0x80075800
 * EN v1.1 Size: 920b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80075684(u8* color, f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, f32 x4, f32 y4)
{
    extern void Camera_RebuildProjectionMatrix(void);
    extern Mtx hudMatrix;
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern void GXSetZMode();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
    extern u8 lbl_803DB679;
    f32 scale = hudScale;
    f32 fy4, fx4, fy3, fx3, fy2, fx2, fy1, fx1;
    fx1 = scale * x1;
    fy1 = scale * y1;
    fx2 = scale * x2;
    fy2 = scale * y2;
    fx3 = scale * x3;
    fy3 = scale * y3;
    fx4 = scale * x4;
    fy4 = scale * y4;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    color[3] = (u8)(((s32)color[3] * (s32)lbl_803DB679) >> 8);
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
    GXWGFifo.s16 = (s16)fx1;
    GXWGFifo.s16 = (s16)fy1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)fx2;
    GXWGFifo.s16 = (s16)fy2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)fx3;
    GXWGFifo.s16 = (s16)fy3;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)fx4;
    GXWGFifo.s16 = (s16)fy4;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80070414
 * EN v1.0 Address: 0x80070414
 * EN v1.0 Size: 856b
 * EN v1.1 Address: 0x80075B98
 * EN v1.1 Size: 832b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void hudDrawTriangle(u8* color, f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3)
{
    extern void Camera_RebuildProjectionMatrix(void);
    extern Mtx hudMatrix;
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern void GXSetZMode();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
    extern u8 lbl_803DB679;
    f32 scale = hudScale;
    f32 fy3, fx3, fy2, fx2, fy1, fx1;
    fx1 = scale * x1;
    fy1 = scale * y1;
    fx2 = scale * x2;
    fy2 = scale * y2;
    fx3 = scale * x3;
    fy3 = scale * y3;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    color[3] = (u8)(((s32)color[3] * (s32)lbl_803DB679) >> 8);
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
    GXWGFifo.s16 = (s16)fx1;
    GXWGFifo.s16 = (s16)fy1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)fx2;
    GXWGFifo.s16 = (s16)fy2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)fx3;
    GXWGFifo.s16 = (s16)fy3;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8007076c
 * EN v1.0 Address: 0x8007076C
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x80075ED8
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80075D5C(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2, int z)
{
    extern void Camera_RebuildProjectionMatrix(void);
    extern Mtx hudMatrix;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
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

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8007089c
 * EN v1.0 Address: 0x8007089C
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80076008
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void textRenderChar(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2)
{
    extern void Camera_RebuildProjectionMatrix(void);
    extern Mtx hudMatrix;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
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

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: drawPartialTexture
 * EN v1.0 Address: 0x800709D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80076144
 * EN v1.1 Size: 1352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void drawPartialTexture(s16* obj, u8 alpha_mod, f32 sx, f32 sy, u16 scale, int width, int height, int u_offset, int v_offset)
{
    extern f32 hudScale;
    extern u8 lbl_803DB679;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern int lbl_803DD014;
    extern void textureFn_8004c264(s16* obj, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    GXColor c;
    s32 w;
    f32 u1, u0, v0, v1;

    c.r = 0xFF;
    c.g = 0xFF;
    c.b = 0xFF;
    c.a = (u8)(((s32)alpha_mod * (s32)lbl_803DB679) >> 8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetTevKColor(0, c);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    if (((u32*)obj)[0x14] != 0) {
        GXSetTevKAlphaSel(1, 0x1C);
        GXSetTevOrder(1, 0, 1, 0xFF);
        GXSetTevDirect(1);
        GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0);
        GXSetTevAlphaIn(1, 7, 4, 6, 7);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
        GXSetNumTevStages(2);
    } else {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    textureFn_8004c264(obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    w = (s32)(((u32)(width << 2) * (u16)scale) >> 8);
    sx = hudScale * sx;
    sy = hudScale * sy;
    u0 = (f32)(u32)u_offset / (f32)((u16*)obj)[5];
    v0 = (f32)(u32)v_offset / (f32)((u16*)obj)[6];
    u1 = (f32)(u32)(width + u_offset) / (f32)((u16*)obj)[5];
    v1 = (f32)(u32)(height + v_offset) / (f32)((u16*)obj)[6];

    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)(((u32)(height << 2) * (u16)scale) >> 8));
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)(((u32)(height << 2) * (u16)scale) >> 8));
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_80076510
 * EN v1.0 Address: 0x80076510
 * EN v1.0 Size: 780b
 * EN v1.1 Address: 0x8007668C
 * EN v1.1 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Generic ortho-projected single-color quad blit. Sets the GX state up
 * fresh (no tex coords, color from constant K0, additive blend, fixed
 * 0x3C texmtx) then emits four GX_VTXFMT1 vertices at z=-0x18C with
 * width 4*size_x and height 4*size_y in screen pixels. Used as the
 * "draw fullscreen tint" primitive by the dialog code in cardShowLoadingMsg.
 */
#pragma peephole off
#pragma scheduling off
void fn_80076510(int x, int y, f32 sx, f32 sy)
{
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern f32 hudScale;
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetColorUpdate(0);
    GXSetTevOrder(0, 0xFF, 0xFF, 4);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xC);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
    GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 1 || lbl_803DD01A == 0) {
        GXSetZMode(1, 7, 1);
        lbl_803DD018 = 1;
        lbl_803DD014 = 7;
        lbl_803DD012 = 1;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 0 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(0);
        lbl_803DD011 = 0;
        lbl_803DD019 = 1;
    }
    GXSetBlendMode(0, 1, 0, 5);
    GXSetCurrentMtx(0x3C);
    sx = hudScale * sx;
    sy = hudScale * sy;
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = -0x18C;

    GXWGFifo.s16 = (s16)(sx + (f32)((u32)x * 4));
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = -0x18C;

    GXWGFifo.s16 = (s16)(sx + (f32)((u32)x * 4));
    GXWGFifo.s16 = (s16)(sy + (f32)((u32)y * 4));
    GXWGFifo.s16 = -0x18C;

    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)(sy + (f32)((u32)y * 4));
    GXWGFifo.s16 = -0x18C;

    Camera_RebuildProjectionMatrix();
    GXSetColorUpdate(1);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: drawScaledTexture
 * EN v1.0 Address: 0x800709E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80076998
 * EN v1.1 Size: 1372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void drawScaledTexture(s16* obj, u8 alpha_mod, f32 sx, f32 sy, u16 scale, int width, int height, u8 flags)
{
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern u8 lbl_803DB679;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern int lbl_803DD014;
    extern void textureFn_8004c264(s16* obj, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    GXColor c;
    s32 w, h;
    f32 u0, u1, v0, v1;
    u8 fbits;

    c.r = 0xFF;
    c.g = 0xFF;
    c.b = 0xFF;
    c.a = (u8)(((s32)alpha_mod * (s32)lbl_803DB679) >> 8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetTevKColor(0, c);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    if (((u32*)obj)[0x14] != 0) {
        GXSetTevKAlphaSel(1, 0x1C);
        GXSetTevOrder(1, 0, 1, 0xFF);
        GXSetTevDirect(1);
        GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0);
        GXSetTevAlphaIn(1, 7, 4, 6, 7);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
        GXSetNumTevStages(2);
    } else {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    textureFn_8004c264(obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    fbits = (u8)flags;
    if ((fbits & 4) != 0) {
        GXSetBlendMode(1, 4, 1, 5);
    } else {
        GXSetBlendMode(1, 4, 5, 5);
    }
    w = (s32)(((u32)(width << 2) * (u16)scale) >> 8);
    h = (s32)(((u32)(height << 2) * (u16)scale) >> 8);
    sx = hudScale * sx;
    sy = hudScale * sy;
    {
        f32 ur = (f32)(u32)width / (f32)(u16)((u16*)obj)[5];
        f32 vr = (f32)(u32)height / (f32)(u16)((u16*)obj)[6];
        if ((fbits & 1) != 0) {
            u0 = ur;
            u1 = lbl_803DEEDC;
        } else {
            u0 = lbl_803DEEDC;
            u1 = ur;
        }
        if ((fbits & 2) != 0) {
            v0 = vr;
            v1 = lbl_803DEEDC;
        } else {
            v0 = lbl_803DEEDC;
            v1 = vr;
        }
    }
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: hudDrawColored
 * EN v1.0 Address: 0x80076D78
 * EN v1.0 Size: 1060b
 * EN v1.1 Address: 0x80076EF4
 * EN v1.1 Size: 1060b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Caller-coloured asset blit. Same mechanic as drawTexture but the K0
 * color comes from a writable GXColor the caller passes in (we apply the
 * lbl_803DB679 alpha tint to it in place). The flag arg picks between
 * "raster passthrough" (TevColorIn 0xF/0xF/0xF/0xE) and "K-tint replace"
 * (TevColorIn 0xF/0xE/0x8/0xF).
 */
#pragma peephole off
#pragma scheduling off
void hudDrawColored(s16* obj, int x, int y, GXColor* color, u16 scale, u8 flag)
{
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern f32 lbl_803DEEE4;
    extern u8 lbl_803DB679;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern int lbl_803DD014;
    extern void textureFn_8004c264(s16* obj, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    color->a = (u8)(((s32)color->a * (s32)lbl_803DB679) >> 8);
    GXSetTevKColor(0, *color);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(0);
    if (flag != 0) {
        GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    } else {
        GXSetTevColorIn(0, 0xF, 0xE, 0x8, 0xF);
    }
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 2, 1, 0);
    if (((u32*)obj)[0x14] != 0) {
        GXSetTevKAlphaSel(1, 0x1C);
        GXSetTevOrder(0, 0, 1, 0xFF);
        GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0);
        GXSetTevAlphaIn(1, 7, 4, 6, 7);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 0, 0, 2, 1, 0);
        GXSetNumTevStages(2);
    } else {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    textureFn_8004c264(obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if (flag != 0) {
        GXSetBlendMode(1, 4, 1, 5);
    } else {
        GXSetBlendMode(1, 4, 5, 5);
    }
    {
        s32 w, h;
        w = ((((u16*)obj)[5] << 2) * (s32)scale) / 256;
        h = ((((u16*)obj)[6] << 2) * (s32)scale) / 256;
        GXBegin(GX_QUADS, GX_VTXFMT1, 4);

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)(x << 2);
        GXWGFifo.s16 = (s16)(y << 2);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = lbl_803DEEDC;
        GXWGFifo.f32 = lbl_803DEEDC;

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)((x << 2) + w);
        GXWGFifo.s16 = (s16)(y << 2);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = lbl_803DEEE4;
        GXWGFifo.f32 = lbl_803DEEDC;

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)((x << 2) + w);
        GXWGFifo.s16 = (s16)((y << 2) + h);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = lbl_803DEEE4;
        GXWGFifo.f32 = lbl_803DEEE4;

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)(x << 2);
        GXWGFifo.s16 = (s16)((y << 2) + h);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = lbl_803DEEDC;
        GXWGFifo.f32 = lbl_803DEEE4;
    }
    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: drawTexture
 * EN v1.0 Address: 0x8007719C
 * EN v1.0 Size: 1128b
 * EN v1.1 Address: 0x80077318
 * EN v1.1 Size: 1128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Quad-from-asset blit: takes an "asset record" (with width at +0xA,
 * height at +0xC, and an optional second-stage flag at +0x50), a per-
 * call alpha multiplier, screen-pos (sx, sy), and a u16 size scale.
 * Composes K0 from RGB(255,255,255) plus the global alpha tint
 * (alpha * lbl_803DB679 >> 8); if the asset opts in, layers a second
 * tex stage that further K-multiplies by the texture. Final width and
 * height are 4 * asset_dim * scale >> 8 in screen pixels at z=-8.
 */
#pragma peephole off
#pragma scheduling off
void drawTexture(s16* obj, u8 alpha_mod, f32 sx, f32 sy, u16 scale)
{
    extern f32 hudScale;
    extern f32 lbl_803DEEDC;
    extern f32 lbl_803DEEE4;
    extern u8 lbl_803DB679;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern int lbl_803DD014;
    extern void textureFn_8004c264(s16* obj, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    GXColor c;
    s32 w, h;

    c.r = 0xFF;
    c.g = 0xFF;
    c.b = 0xFF;
    c.a = (u8)(((s32)alpha_mod * (s32)lbl_803DB679) >> 8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetTevKColor(0, c);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevDirect(0);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(0, 7, 4, 6, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    if (((u32*)obj)[0x14] != 0) {
        GXSetTevKAlphaSel(1, 0x1C);
        GXSetTevOrder(1, 0, 1, 0xFF);
        GXSetTevDirect(1);
        GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0);
        GXSetTevAlphaIn(1, 7, 4, 6, 7);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);
        GXSetNumTevStages(2);
    } else {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    textureFn_8004c264(obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    w = ((((u16*)obj)[5] << 2) * (s32)scale) / 256;
    h = ((((u16*)obj)[6] << 2) * (s32)scale) / 256;
    sx = hudScale * sx;
    sy = hudScale * sy;
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEE4;
    GXWGFifo.f32 = lbl_803DEEDC;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEE4;
    GXWGFifo.f32 = lbl_803DEEE4;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = lbl_803DEEDC;
    GXWGFifo.f32 = lbl_803DEEE4;

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_800709ec
 * EN v1.0 Address: 0x800709EC
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x80077780
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80077604(f32* obj, u32* colorPtr, Mtx mtx)
{
    extern void fn_8004C460(int, int);
    extern GXColor lbl_803DC308;
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
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
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80070c74
 * EN v1.0 Address: 0x80070C74
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x80077A08
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_8007788C(f32* obj, u32* colorPtr, Mtx mtx)
{
    extern void fn_8004C460(int, int);
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
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
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_80077AD8
 * EN v1.0 Address: 0x80070EC0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80077C54
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80077AD8(double param_1,float *param_2,int param_3,float *param_4)
{
}

/*
 * --INFO--
 *
 * Function: fn_80077EF8
 * EN v1.0 Address: 0x80070EC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80078074
 * EN v1.1 Size: 2120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80077EF8(void* obj, u8* node, Mtx mtx, double scale)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern u32 lbl_803DEEAC;
    extern u32 lbl_803DEEB0;
    extern u32 lbl_803E8450;
    extern f32 lbl_803DD024, lbl_803DD020, lbl_803DD038, lbl_803DD034;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern u8 lbl_802C1EA8[0xC0];
    extern void selectTexture(int handle, int slot);
    extern void fn_8006C5B8(int* out);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_e0;
    Mtx mtx_110;
    f32 buf_38[8];
    f32 buf_54[8];
    f32 buf_70[8];
    f32 buf_8c[8];
    f32 buf_a8[8];
    f32 buf_c4[8];
    GXColor temp;
    GXColor color2;
    f32 fog_var;
    f32 vec3[3];
    int handle;
    int stage_idx;
    int stage_count;
    int stage_base;
    f32 f31_val;

    /* Copy table from lbl_802C1EA8 */
    {
        u32* src = (u32*)(lbl_802C1EA8 + 0x18);
        u32* dst1 = (u32*)buf_c4; /* +0xC4 in stack */
        int i;
        for (i = 0; i < 7; i++) dst1[i] = src[i];
        /* additional unrolled copies to scattered slots */
        {
            u32* src2 = (u32*)(lbl_802C1EA8 + 0x34);
            u32* dst2 = (u32*)buf_a8;
            for (i = 0; i < 7; i++) dst2[i] = src2[i];
        }
        {
            u32* src3 = (u32*)(lbl_802C1EA8 + 0x50);
            u32* dst3 = (u32*)buf_8c;
            for (i = 0; i < 7; i++) dst3[i] = src3[i];
        }
        {
            u32* src4 = (u32*)(lbl_802C1EA8 + 0x6C);
            u32* dst4 = (u32*)buf_70;
            for (i = 0; i < 7; i++) dst4[i] = src4[i];
        }
        {
            u32* src5 = (u32*)(lbl_802C1EA8 + 0x88);
            u32* dst5 = (u32*)buf_54;
            for (i = 0; i < 7; i++) dst5[i] = src5[i];
        }
        {
            u32* src6 = (u32*)(lbl_802C1EA8 + 0xA4);
            u32* dst6 = (u32*)buf_38;
            for (i = 0; i < 7; i++) dst6[i] = src6[i];
        }
    }
    *(u32*)&color2 = lbl_803DEEAC;
    *(u16*)((u8*)&temp + 0) = (u16)lbl_803DEEB0;
    ((u8*)&temp)[2] = (u8)(lbl_803DEEB0 >> 8);
    fog_var = (f32)lbl_803E8450;

    PSMTXConcat((f32(*)[4])((u8*)lbl_802C1EA8 + 0xB8), mtx, mtx_110);
    GXLoadTexMtxImm(mtx_110, 0x1e, 1);
    GXSetTexCoordGen2(0, 1, 0, 0x1e, 0, 0x7d);

    selectTexture(*(int*)((u8*)obj + 0x60), 0);

    if (((u8*)obj)[0x65] < 8) {
        GXSetTevSwapModeTable(1, 0, 0, 0, 0);
        stage_idx = ((u8*)obj)[0x65] - 1;
    } else if (((u8*)obj)[0x65] < 0x10) {
        GXSetTevSwapModeTable(1, 3, 3, 3, 3);
        stage_idx = ((u8*)obj)[0x65] - 9;
    } else {
        stage_idx = 0;
    }
    if (stage_idx < 0) stage_idx = 0;

    /* Set TevColor 1 = (0x7F, 0x7F, 0x7F, 0) */
    ((u8*)&color2)[0] = 0x7F;
    ((u8*)&color2)[1] = 0x7F;
    ((u8*)&color2)[2] = 0x7F;
    GXSetTevColor(1, color2);

    /* Modify node[3] (alpha-like) */
    node[3] = (u8)((node[3] >> 1) + (node[3] >> 2));
    ((u8*)&temp)[0] = node[3];
    ((u8*)&temp)[1] = node[3];
    ((u8*)&temp)[2] = node[3];
    GXSetTevKColor(0, temp);

    stage_base = 0;
    stage_count = ((u8*)buf_c4)[0];  /* indexed by stage_idx but for skel we just ignore */
    if (stage_count != 0) {
        GXSetTevDirect(0);
        GXSetTevSwapMode(0, 0, 1);
        GXSetTevOrder(0, 0, 0, 0xFF);
        GXSetTevColorIn(0, 0xF, 0x8, 0xC, ((u8*)buf_c4)[stage_idx * 4]);
        GXSetTevAlphaIn(0, 7, 7, 7, 7);
        GXSetTevColorOp(0, 0, 0, ((u8*)buf_a8)[stage_idx * 4], 0, 0);
        GXSetTevAlphaOp(0, 0, 0, 0, 0, 0);
        stage_base = 1;
    }

    if (stage_count > 1) {
        GXSetTevDirect(stage_base);
        GXSetTevSwapMode(stage_base, 0, 0);
        GXSetTevOrder(stage_base, 0xFF, 0xFF, 0xFF);
        GXSetTevColorIn(stage_base, 0xF, 0, 0xC, ((u8*)buf_70)[stage_idx * 4]);
        GXSetTevAlphaIn(stage_base, 7, 7, 7, 7);
        GXSetTevColorOp(stage_base, 0, 0, ((u8*)buf_70)[stage_idx * 4], 0, 0);
        GXSetTevAlphaOp(stage_base, 0, 0, 0, 0, 0);
        stage_base++;
    }

    if (stage_count > 2) {
        GXSetTevDirect(stage_base);
        GXSetTevSwapMode(stage_base, 0, 0);
        GXSetTevOrder(stage_base, 0xFF, 0xFF, 0xFF);
        GXSetTevColorIn(stage_base, 0xF, 0, 0xC, ((u8*)buf_54)[stage_idx * 4]);
        GXSetTevAlphaIn(stage_base, 7, 7, 7, 7);
        GXSetTevColorOp(stage_base, 0, 0, ((u8*)buf_38)[stage_idx * 4], 0, 0);
        GXSetTevAlphaOp(stage_base, 0, 0, 0, 0, 0);
        stage_base++;
    }

    GXSetTevDirect(stage_base);
    GXSetTevSwapMode(stage_base, 0, 0);
    GXSetTevKColorSel(stage_base, 0xC);
    GXSetTevOrder(stage_base, 0xFF, 0xFF, 0xFF);
    if (stage_count == 0) {
        GXSetTevColorIn(stage_base, 8, 2, 0xE, 0xF);
    } else {
        GXSetTevColorIn(stage_base, 0, 2, 0xE, 0xF);
    }
    GXSetTevAlphaIn(stage_base, 7, 7, 7, 7);
    GXSetTevColorOp(stage_base, 8, 0, 0, 1, 0);
    GXSetTevAlphaOp(stage_base, 0, 0, 0, 1, 0);

    /* Build second tex matrix (slot 0x21) */
    vec3[0] = mtx[0][3];
    vec3[1] = mtx[1][3];
    vec3[2] = mtx[2][3];
    PSMTXMultVec((f32(*)[4])((u8*)obj + 0x30), (Vec*)vec3, (Vec*)vec3);
    f31_val = -vec3[2];

    fn_8006C5B8(&handle);
    selectTexture(handle, 1);

    {
        f32 d = f31_val - (f32)scale;
        f32 d2 = f31_val - d;
        mtx_110[0][0] = lbl_803DEEDC;
        mtx_110[0][1] = lbl_803DEEDC;
        mtx_110[0][2] = lbl_803DEEE4 / d2;
        mtx_110[0][3] = f31_val / d2;
        mtx_110[1][0] = lbl_803DEEDC;
        mtx_110[1][1] = lbl_803DEEDC;
        mtx_110[1][2] = lbl_803DEEDC;
        mtx_110[1][3] = lbl_803DEEDC;
    }
    PSMTXConcat((f32(*)[4])((u8*)obj + 0x30), mtx, mtx_e0);
    PSMTXConcat(mtx_110, mtx_e0, mtx_e0);
    GXLoadTexMtxImm(mtx_e0, 0x21, 1);
    GXSetTexCoordGen2(1, 1, 0, 0x21, 0, 0x7d);

    GXSetTevDirect(stage_base + 1);
    GXSetTevSwapMode(stage_base + 1, 0, 0);
    GXSetTevOrder(stage_base + 1, 1, 1, 0xFF);
    GXSetTevColorIn(stage_base + 1, 0, 0xF, 8, 0xF);
    GXSetTevAlphaIn(stage_base + 1, 7, 7, 7, 7);
    GXSetTevColorOp(stage_base + 1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(stage_base + 1, 0, 0, 0, 1, 0);

    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(2);
    GXSetNumTevStages((u8)(stage_count + 2));

    {
        GXColor fc;
        *(u32*)&fc = lbl_803E8450;
        GXSetFog(4, lbl_803DD024, lbl_803DD020, lbl_803DD038, lbl_803DD034, fc);
    }
    GXSetBlendMode(1, 0, 3, 5);

    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80070ec8
 * EN v1.0 Address: 0x80070EC8
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x800788BC
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078740(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 1 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 1);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 1;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(0, 1, 0, 5);
    if ((u32)lbl_803DD011 != 1 || lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80070f94
 * EN v1.0 Address: 0x80070F94
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x80078988
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_8007880C(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(0, 1, 0, 5);
    if ((u32)lbl_803DD011 != 1 || lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071064
 * EN v1.0 Address: 0x80071064
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x80078A58
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800788DC(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 1, 5);
    if ((u32)lbl_803DD011 != 1 || lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071134
 * EN v1.0 Address: 0x80071134
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x80078B28
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800789AC(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 1, 5);
    if ((u32)lbl_803DD011 != 1 || lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071204
 * EN v1.0 Address: 0x80071204
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x80078BF8
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void textBlendSetupFn_80078a7c(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD011 != 1 || lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800712d4
 * EN v1.0 Address: 0x800712D4
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x80078CC8
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078B4C(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD011 != 1 || lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800713a4
 * EN v1.0 Address: 0x800713A4
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x80078D98
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078C1C(void)
{
    extern void GXSetZMode();
    extern void GXSetZCompLoc();
    extern u8 lbl_803DD012;
    extern int lbl_803DD014;
    extern u8 lbl_803DD018;
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
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD011 != 1 || lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071584
 * EN v1.0 Address: 0x80071584
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x80078F78
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078DFC(void)
{
    GXSetTevOrder(lbl_803DDCB0, 0xFF, 0xFF, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0, 10, 0xF);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 0, 5, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DD00B += 1;
    lbl_803DD009 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071658
 * EN v1.0 Address: 0x80071658
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x8007904C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80078ED0(void)
{
    GXSetTevOrder(lbl_803DDCB0, 0xFF, 0xFF, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 10, 4, 0xF);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 5, 2, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DD00B += 1;
    lbl_803DD009 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007172c
 * EN v1.0 Address: 0x8007172C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80079120
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void textRenderSetup(void)
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
    lbl_803DD00B += 1;
    lbl_803DDCAC += 1;
    lbl_803DD00A += 1;
    lbl_803DDCA8 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071834
 * EN v1.0 Address: 0x80071834
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x80079228
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800790AC(void)
{
    GXSetTevOrder(lbl_803DDCB0, 0xFF, 0xFF, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0xF, 0xF, 4);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 7, 7, 2);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DD00B += 1;
    lbl_803DD009 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071908
 * EN v1.0 Address: 0x80071908
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x800792FC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80079180(void)
{
    GXSetTevOrder(lbl_803DDCB0, 0xFF, 0xFF, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0xF, 0xF, 10);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 7, 7, 5);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DD00B += 1;
    lbl_803DD009 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800719dc
 * EN v1.0 Address: 0x800719DC
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x800793D0
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80079254(void)
{
    GXSetTevOrder(lbl_803DDCB0, 0xFF, 0xFF, 4);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0, 4, 0xF);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 0, 2, 7);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DD00B += 1;
    lbl_803DD009 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071ab0
 * EN v1.0 Address: 0x80071AB0
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x800794A4
 * EN v1.1 Size: 440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80079328(void)
{
    GXSetTevOrder(lbl_803DDCB0, lbl_803DDCAC, lbl_803DDCA8, 0xFF);
    GXSetTevDirect(lbl_803DDCB0);
    GXSetTevColorIn(lbl_803DDCB0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(lbl_803DDCB0, 7, 7, 7, 4);
    GXSetTevSwapMode(lbl_803DDCB0, 0, 0);
    GXSetTevColorOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DDCB0, 0, 0, 0, 1, 0);
    lbl_803DDCB0 += 1;
    lbl_803DD00B += 1;
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
    lbl_803DD00B += 1;
    lbl_803DDCAC += 1;
    lbl_803DD00A += 1;
    lbl_803DDCA8 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071c68
 * EN v1.0 Address: 0x80071C68
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x8007965C
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800794E0(void)
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
    lbl_803DD00B += 1;
    lbl_803DDCA8 += 1;
    lbl_803DDCAC += 1;
    lbl_803DD00A += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071d70
 * EN v1.0 Address: 0x80071D70
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80079764
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void textRenderSetupFn_800795e8(void)
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
    lbl_803DD00B += 1;
    lbl_803DDCA8 += 1;
    lbl_803DDCAC += 1;
    lbl_803DD00A += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80071e78
 * EN v1.0 Address: 0x80071E78
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x8007986C
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_800796F0(void)
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
    lbl_803DD00B += 1;
    lbl_803DDCA8 += 1;
    lbl_803DDCAC += 1;
    lbl_803DD00A += 1;
    lbl_803DD009 += 1;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: textRenderSetupFn_80079804
 * EN v1.0 Address: 0x80079804
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x80079980
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Closes out the TEV pipeline configuration that fn_80079A64 etc. open:
 * pushes the current ind-stage / chan-ctrl / tex-gen counts in
 * lbl_803DD008..00B back into GX, and if the global tint alpha
 * lbl_803DB679 isn't fully transparent (0xFF) appends one final TEV
 * stage that K-multiplies the tint over the existing color, advancing
 * lbl_803DD030 (TEV stage cursor) and lbl_803DD00B (stage count).
 */
#pragma peephole off
#pragma scheduling off
void textRenderSetupFn_80079804(void)
{
    extern u8 lbl_803DD008, lbl_803DD009, lbl_803DD00A, lbl_803DD00B;
    extern u8 lbl_803DB679;
    extern u32 lbl_803DD030;
    GXColor c;

    GXSetNumIndStages(lbl_803DD008);
    if (lbl_803DD009 != 0) {
        GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
        GXSetNumChans(1);
    } else {
        GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
        GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
        GXSetNumChans(0);
    }
    GXSetNumTexGens(lbl_803DD00A);
    if (lbl_803DB679 < 0xFF) {
        c.a = lbl_803DB679;
        GXSetTevKColor(0, c);
        GXSetTevKAlphaSel(lbl_803DD030, 0x1C);
        GXSetTevOrder(lbl_803DD030, 0xFF, 0xFF, 0xFF);
        GXSetTevDirect(lbl_803DD030);
        GXSetTevColorIn(lbl_803DD030, 0xF, 0xF, 0xF, 0);
        GXSetTevAlphaIn(lbl_803DD030, 7, 0, 6, 7);
        GXSetTevSwapMode(lbl_803DD030, 0, 0);
        GXSetTevColorOp(lbl_803DD030, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DD030, 0, 0, 0, 1, 0);
        lbl_803DD030 = lbl_803DD030 + 1;
        lbl_803DD00B = lbl_803DD00B + 1;
    }
    GXSetNumTevStages(lbl_803DD00B);
    if (lbl_803DD009 != 0) {
        GXSetChanCtrl(4, 0, 0, 1, 0, 0, 2);
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80071f90
 * EN v1.0 Address: 0x80071F90
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80079B3C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void textureSetupFn_800799c0(void)
{
    lbl_803DDC88 = 0;
    lbl_803DD009 = 0;
    lbl_803DD00A = 0;
    lbl_803DD00B = 0;
    lbl_803DDCB0 = 0;
    lbl_803DDCAC = 0;
    lbl_803DDCA8 = 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80071fb4
 * EN v1.0 Address: 0x80071FB4
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80079B60
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void _gxSetTevColor2(u8 r, u8 g, u8 b, u8 a)
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
 * Function: FUN_80071ff4
 * EN v1.0 Address: 0x80071FF4
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80079BA0
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void _gxSetTevColor1(u8 r, u8 g, u8 b, u8 a)
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
 * Function: fn_80079A64
 * EN v1.0 Address: 0x80079A64
 * EN v1.0 Size: 1024b
 * EN v1.1 Address: 0x80079BE0
 * EN v1.1 Size: 1024b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Fullscreen 640x480 texture-tinted quad with shape-controlled alpha:
 * `flag != 0` lights the screen with three pre-set GXColors stamped into
 * K0/T1/T2; `flag == 0` instead does a single K0 modulate where K0's
 * alpha is the caller's byte divided by 4. Builds a per-call 3x4 tex
 * coord matrix that scales the source texture by 1/sx and 1/sy with a
 * sub-pixel offset baked from lbl_803DEF4C/50.
 */
#pragma peephole off
#pragma scheduling off
void fn_80079A64(f32 sx, f32 sy, u8 a, u8 flag)
{
    extern u32 lbl_803DEEA0;
    extern u32 lbl_803DEEA4;
    extern u32 lbl_803DEEA8;
    extern f32 lbl_803DEEDC;
    extern f32 gSynthDelayedActionWord0;
    extern f32 lbl_803DEEE4;
    extern f32 lbl_803DEF4C;
    extern f32 lbl_803DEF50;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern void fn_8006C540(int*);
    extern void selectTexture(int, int);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    int handle;
    GXColor c0, c1, c2;
    Mtx mtx;

    *(u32*)&c0 = lbl_803DEEA0;
    *(u32*)&c1 = lbl_803DEEA4;
    *(u32*)&c2 = lbl_803DEEA8;
    fn_8006C540(&handle);
    selectTexture(handle, 0);
    {
        f32 dec = gSynthDelayedActionWord0;
        f32 zero = lbl_803DEEDC;
        f32 inv_sx = dec / sx;
        f32 inv_sy = dec / sy;
        mtx[0][0] = inv_sx;
        mtx[0][1] = zero;
        mtx[0][2] = zero;
        mtx[0][3] = lbl_803DEF4C * inv_sx + dec;
        mtx[1][0] = zero;
        mtx[1][1] = inv_sy;
        mtx[1][2] = zero;
        mtx[1][3] = lbl_803DEF50 * inv_sy + dec;
        mtx[2][0] = zero;
        mtx[2][1] = zero;
        mtx[2][2] = zero;
        mtx[2][3] = lbl_803DEEE4;
    }
    GXSetTexCoordGen2(0, 1, 0, 0x1E, 0, 0x7D);
    GXLoadTexMtxImm(mtx, 0x1E, 1);
    GXSetTevKColorSel(0, 0xC);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xE);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    if (flag != 0) {
        c0.a = a;
        GXSetTevKColor(0, c0);
        GXSetTevColor(1, c1);
        GXSetTevColor(2, c2);
        GXSetTevAlphaIn(0, 4, 1, 2, 6);
        GXSetTevAlphaOp(0, 0xE, 0, 0, 1, 0);
    } else {
        c0.a = (u8)((s32)a >> 2);
        GXSetTevKColor(0, c0);
        GXSetTevAlphaIn(0, 4, 7, 7, 6);
        GXSetTevAlphaOp(0, 0, 0, 2, 1, 0);
    }
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXClearVtxDesc();
    GXSetCurrentMtx(0x3C);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 5, 4, 5);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;

    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(0);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_80079E64
 * EN v1.0 Address: 0x80072038
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80079FE0
 * EN v1.1 Size: 2232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_80079E64(double s1, double s2, double s3, u8 mtxIdx, void* vec, u8 alpha0, u8 alpha1)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4, lbl_803DEEF4;
    extern f32 lbl_803DEF54, lbl_803DEF58, lbl_803DEF5C, lbl_803DEF60, lbl_803DEF64, lbl_803DEF68;
    extern f32 lbl_803DD00C;
    extern f32 gSynthFadeMask, gSynthDelayedActionWord0, timeDelta;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern u16 fn_8000FA90(void);
    extern u16 fn_8000FA70(void);
    extern int fn_8002073C(void);
    extern f32 fn_80292194(f32 v);
    extern f32 fn_80021370(f32 a, f32 b, f32 c);
    extern void getReflectionTexture2(int* out);
    extern void fn_8006C4F8(int* out);
    extern void selectTexture(int handle, int slot);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_28;
    Mtx mtx_58;
    int handle1;
    int handle2;
    f32 ratio1;
    f32 ratio2;
    f32 angle;
    GXColor c_K0;
    GXColor c_K1;
    GXColor c_K2;

    c_K0.a = alpha0;
    c_K1.a = alpha1;
    ratio1 = ((f32)(u32)fn_8000FA90() - lbl_803DEF54) / lbl_803DEF58;
    ratio2 = ((f32)(u32)fn_8000FA70() - lbl_803DEF54) / lbl_803DEF58;
    if (fn_8002073C() != 0) {
        angle = lbl_803DD00C;
    } else {
        f32 t = fn_80292194(((f32*)vec)[0] / ((f32*)vec)[1]);
        angle = lbl_803DD00C + fn_80021370(t - lbl_803DD00C, lbl_803DEF5C, timeDelta);
        lbl_803DD00C = angle;
    }
    c_K2.a = mtxIdx;

    getReflectionTexture2(&handle1);
    selectTexture(handle1, 0);
    fn_8006C4F8(&handle2);
    selectTexture(handle2, 1);

    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);

    PSMTXScale(mtx_58, lbl_803DEF60 * (f32)s2, lbl_803DEF60 * (f32)s2, lbl_803DEEDC);
    PSMTXTrans(mtx_28, ratio1 * (f32)s3, ratio2 * (f32)s3 + (f32)s1, lbl_803DEEDC);
    PSMTXConcat(mtx_28, mtx_58, mtx_58);
    PSMTXRotRad(mtx_28, 'z', angle);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    PSMTXTrans(mtx_28, lbl_803DEEF4, lbl_803DEEF4, lbl_803DEEDC);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    GXLoadTexMtxImm(mtx_58, 0x1e, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x1e, 0, 0x7d);

    PSMTXScale(mtx_58, lbl_803DEF64 * (f32)s2, lbl_803DEF64 * (f32)s2, lbl_803DEEDC);
    PSMTXTrans(mtx_28, gSynthFadeMask * ratio1 * (f32)s3,
                       lbl_803DEF68 * (f32)s1 + gSynthFadeMask * ratio2 * (f32)s3,
                       lbl_803DEEDC);
    PSMTXConcat(mtx_28, mtx_58, mtx_58);
    PSMTXRotRad(mtx_28, 'z', gSynthDelayedActionWord0 * angle);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    PSMTXTrans(mtx_28, lbl_803DEEF4, lbl_803DEEF4, lbl_803DEEDC);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    GXLoadTexMtxImm(mtx_58, 0x21, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x21, 0, 0x7d);

    /* TEV stages 0..5 */
    GXSetTevKColor(0, c_K0);
    GXSetTevKAlphaSel(0, 0x1C);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0, 0, 0xFF);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(0, 0, 6, 7, 4);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 1, 2, 1, 0);

    GXSetTevDirect(1);
    GXSetTevOrder(1, 1, 1, 0xFF);
    GXSetTevColorIn(1, 1, 8, 0xF, 0xF);
    GXSetTevAlphaIn(1, 0, 7, 4, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 1, 1, 0);

    GXSetTevKColor(1, c_K1);
    GXSetTevKAlphaSel(2, 0x1D);
    GXSetTevDirect(2);
    GXSetTevOrder(2, 0, 0, 0xFF);
    GXSetTevColorIn(2, 0xF, 0xF, 0xF, 0xF);
    GXSetTevAlphaIn(2, 0, 6, 7, 4);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(2, 0, 1, 2, 1, 1);

    GXSetTevDirect(3);
    GXSetTevOrder(3, 2, 1, 0xFF);
    GXSetTevColorIn(3, 1, 8, 0xF, 0xF);
    GXSetTevAlphaIn(3, 0, 7, 4, 7);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevColorOp(3, 0, 0, 0, 1, 1);
    GXSetTevAlphaOp(3, 0, 0, 1, 1, 1);

    GXSetTevKAlphaSel(4, 0);
    GXSetTevDirect(4);
    GXSetTevOrder(4, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(4, 0, 2, 3, 0xF);
    GXSetTevAlphaIn(4, 0, 6, 1, 7);
    GXSetTevSwapMode(4, 0, 0);
    GXSetTevColorOp(4, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(4, 0, 0, 0, 1, 0);

    GXSetTevKColor(2, c_K2);
    GXSetTevKAlphaSel(5, 0x1E);
    GXSetTevDirect(5);
    GXSetTevOrder(5, 0xFF, 0xFF, 0xFF);
    GXSetTevColorIn(5, 0xF, 0xF, 0xF, 0);
    GXSetTevAlphaIn(5, 0, 6, 7, 0);  /* Note: target has 0, 0, 6, 7 — adjust */
    GXSetTevSwapMode(5, 0, 0);
    GXSetTevColorOp(5, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(5, 0, 0, 0, 1, 0);

    GXSetNumTexGens(3);
    GXSetNumTevStages(6);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);

    GXClearVtxDesc();
    GXSetCurrentMtx(0x3C);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 1 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 1, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 1;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(0);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_8007A71C
 * EN v1.0 Address: 0x8007203C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007A898
 * EN v1.1 Size: 1524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007A71C(u32 alpha_in)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 lbl_803DEF6C, lbl_803DEF70, lbl_803DEF74;
    extern f32 gSynthDelayedActionWord0;
    extern u32 lbl_803DB6A4;
    extern u8 lbl_802C1EA8[];
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern s16 fn_8000FA70(void);
    extern void selectReflectionTexture(int);
    extern void getReflectionTexture2(int* out);
    extern void getTextureFn_8006c5e4(int* out);
    extern void fn_8006CABC(f32* a, f32* b);
    extern void fn_80293C64(f32* a, f32* b, f32 c);
    extern void selectTexture(int handle, int slot);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    f32 indMtx[6];
    Mtx mtx_44;
    int handle1, handle2;
    f32 fA, fB;
    f32 mulX, mulY;
    int alpha_clamp;
    int alpha_final;
    GXColor temp;

    /* Copy 24 bytes from lbl_802C1EA8 (6 floats) to local stack */
    {
        u32* src = (u32*)lbl_802C1EA8;
        u32* dst = (u32*)indMtx;
        int i;
        for (i = 0; i < 6; i++) dst[i] = src[i];
    }

    /* Compute alpha clamp from fn_8000FA70 */
    {
        s16 v = fn_8000FA70();
        if (v < 0) {
            int x = ((u16)v >> 8) - 0xC0;
            alpha_clamp = (x << 2) & 0xFF;
        } else {
            alpha_clamp = 0xFF;
        }
    }
    /* alpha_in *= 0xFF/256 */
    alpha_in = ((alpha_in & 0xFF) * 0xFF) >> 8;
    alpha_final = (alpha_clamp * (alpha_in & 0xFF)) >> 8;

    selectReflectionTexture(0);
    getReflectionTexture2(&handle1);
    selectTexture(handle1, 1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);

    fn_8006CABC(&fA, &fB);
    fA *= lbl_803DEF6C;
    fB *= lbl_803DEF6C;
    getTextureFn_8006c5e4(&handle2);
    selectTexture(handle2, 2);

    fn_80293C64(&mulX, &mulY, lbl_803DEF70 * fA);
    mulY *= gSynthDelayedActionWord0;
    mulX *= gSynthDelayedActionWord0;

    indMtx[0] = mulY;
    indMtx[1] = mulX;
    indMtx[2] = lbl_803DEEDC;
    indMtx[3] = -mulX;
    indMtx[4] = mulY;
    indMtx[5] = lbl_803DEEDC;

    PSMTXScale(mtx_44, lbl_803DEF74, lbl_803DEF74, lbl_803DEEE4);
    mtx_44[0][3] = fA;
    mtx_44[2][3] = -fB;
    GXLoadTexMtxImm(mtx_44, 0x40, 0);
    GXSetTexCoordGen2(1, 0, 4, 0x3C, 0, 0x40);

    GXSetIndTexOrder(0, 1, 2);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx, -6);
    GXSetTevIndirect(1, 0, 0, 7, 1, 0, 0, 0, 0, 0);

    *(u32*)&temp = lbl_803DB6A4;
    GXSetTevKColor(0, temp);
    GXSetTevKAlphaSel(0, 0x1c);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0, 1, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xf);
    GXSetTevAlphaIn(0, 6, 7, 7, 4);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 1, 0, 2, 1, 0);

    GXSetTevOrder(1, 0, 0, 0xff);
    GXSetTevColorIn(1, 8, 0xf, 0xf, 0xf);
    GXSetTevAlphaIn(1, 7, 7, 7, 0);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    GXSetNumIndStages(1);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);

    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

/*
 * --INFO--
 *
 * Function: fn_8007AD10
 * EN v1.0 Address: 0x8007AD10
 * EN v1.0 Size: 780b
 * EN v1.1 Address: 0x8007AE8C
 * EN v1.1 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Fullscreen 640x480 textured quad with caller-supplied alpha. The alpha
 * is multiplied by lbl_803DEF20 (a 0..255 scale), fctiwz'd to int and
 * stamped into byte 3 of the K0 GXColor cache (lbl_803DB6A0). Sets up
 * one TEV stage that K-multiplies the texture by alpha; uses fixed UVs
 * 0..0x80 so the texture maps once across the screen. Used when fading
 * the screen to texture (e.g. boot logo / "now loading").
 */
#pragma peephole off
#pragma scheduling off
void fn_8007AD10(f32 alpha)
{
    extern struct { f32 x, y; } lbl_803DEF1C;
    extern GXColor lbl_803DB6A0;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern void selectReflectionTexture(int);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx;

    lbl_803DB6A0.a = lbl_803DEF1C.y * alpha;
    selectReflectionTexture(0);
    GXSetTevKColor(0, lbl_803DB6A0);
    GXSetTevKAlphaSel(0, 0x1C);
    PSMTXIdentity(mtx);
    GXLoadTexMtxImm(mtx, 0x24, 1);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);
    GXSetTevDirect(0);
    GXSetTevOrder(0, 0, 0, 6);
    GXSetTevColorIn(0, 0xF, 0xF, 0xF, 8);
    GXSetTevAlphaIn(0, 7, 7, 7, 6);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_8007B01C
 * EN v1.0 Address: 0x80072044
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007B198
 * EN v1.1 Size: 3440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_8007B01C(double wx, double wy, double wz, char param4, char param5)
{
    extern f32 playerMapOffsetX, playerMapOffsetZ;
    extern f32 lbl_803DEEE4;
    extern f32 lbl_803DEF08;
    extern f32 lbl_803DEF78, lbl_803DEF7C, lbl_803DEF80;
    extern u32 lbl_803DB69C;
    extern Mtx hudMatrix;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern void selectReflectionTexture(int);
    extern void getReflectionTexture2(int* out);
    extern void selectTexture(int handle, int slot);
    extern void Camera_ProjectWorldPoint(f32* out_x, f32* out_y, f32* out_z, f32* out_w, double x, double y, double z);
    extern void Camera_RebuildProjectionMatrix(void);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_27;
    Mtx mtx_24;
    Mtx mtx_2A;
    Mtx mtx_2D;
    Mtx mtx_30;
    GXColor c1;
    GXColor c0;
    int handle;
    f32 pz, px, py, pw;
    int stage_base;

    wx = wx - playerMapOffsetX;
    wz = wz - playerMapOffsetZ;
    Camera_ProjectWorldPoint(&px, &py, &pz, &pw, wx, wy, wz);
    pz = pz + lbl_803DEEE4;
    c0.a = (u8)(((u32)(lbl_803DEF08 * pz) & 0x00FF0000) >> 16);
    selectReflectionTexture(0);
    getReflectionTexture2(&handle);
    selectTexture(handle, 1);
    GXSetTevSwapModeTable(1, 0, 0, 0, 1);

    PSMTXIdentity(mtx_24);
    mtx_24[1][3] = lbl_803DEF78;
    GXLoadTexMtxImm(mtx_24, 0x24, 1);
    GXSetTexCoordGen2(0, 1, 4, 0x24, 0, 0x7D);

    PSMTXIdentity(mtx_2A);
    mtx_2A[1][3] = lbl_803DEF78;
    GXLoadTexMtxImm(mtx_2A, 0x2A, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x2A, 0, 0x7D);

    PSMTXIdentity(mtx_2D);
    mtx_2D[0][3] = lbl_803DEF7C;
    GXLoadTexMtxImm(mtx_2D, 0x2D, 1);
    GXSetTexCoordGen2(3, 1, 4, 0x2D, 0, 0x7D);

    PSMTXIdentity(mtx_30);
    mtx_30[0][3] = lbl_803DEF80;
    GXLoadTexMtxImm(mtx_30, 0x30, 1);
    GXSetTexCoordGen2(4, 1, 4, 0x30, 0, 0x7D);

    GXSetTexCoordGen2(5, 1, 4, 0x3C, 0, 0x7D);

    PSMTXIdentity(mtx_27);
    GXLoadTexMtxImm(mtx_27, 0x27, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x27, 0, 0x7D);

    GXSetTevKColor(0, c0);
    GXSetTevKAlphaSel(0, 0x1C);
    c1 = *(GXColor*)&lbl_803DB69C;
    GXSetTevKColor(1, c1);

    GXSetNumTexGens(6);
    GXSetNumIndStages(0);
    GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
    GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
    GXSetNumChans(0);

    stage_base = 0;
    if ((u8)param5 != 0) {
        /* path C: 7 stages, all literal indices */
        GXSetTevKAlphaSel(1, 0x1C);
        GXSetNumTevStages(7);

        GXSetTevDirect(0);
        GXSetTevOrder(0, 1, 1, 0xFF);
        GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xF);
        GXSetTevAlphaIn(0, 4, 7, 7, 6);
        GXSetTevSwapMode(0, 0, 0);
        GXSetTevColorOp(0, 0, 0, 0, 1, 3);
        GXSetTevAlphaOp(0, 1, 0, 0, 1, 3);

        GXSetTevDirect(1);
        GXSetTevOrder(1, 1, 1, 0xFF);
        GXSetTevColorIn(1, 0xF, 0xF, 0xF, 0xF);
        GXSetTevAlphaIn(1, 6, 7, 7, 4);
        GXSetTevSwapMode(1, 0, 0);
        GXSetTevColorOp(1, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(1, 1, 0, 0, 1, 0);

        GXSetTevKColorSel(2, 0xD);
        GXSetTevDirect(2);
        GXSetTevOrder(2, 0, 0, 0xFF);
        GXSetTevColorIn(2, 0xF, 0x8, 0xE, 0xF);
        GXSetTevAlphaIn(2, 0, 7, 7, 3);
        GXSetTevSwapMode(2, 0, 0);
        GXSetTevColorOp(2, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(2, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(3, 0xD);
        GXSetTevDirect(3);
        GXSetTevOrder(3, 2, 0, 0xFF);
        GXSetTevColorIn(3, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(3, 7, 7, 7, 0);
        GXSetTevSwapMode(3, 0, 0);
        GXSetTevColorOp(3, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(3, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(4, 0xD);
        GXSetTevDirect(4);
        GXSetTevOrder(4, 3, 0, 0xFF);
        GXSetTevColorIn(4, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(4, 7, 7, 7, 0);
        GXSetTevSwapMode(4, 0, 0);
        GXSetTevColorOp(4, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(4, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(5, 0xD);
        GXSetTevDirect(5);
        GXSetTevOrder(5, 4, 0, 0xFF);
        GXSetTevColorIn(5, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(5, 7, 7, 7, 0);
        GXSetTevSwapMode(5, 0, 0);
        GXSetTevColorOp(5, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(5, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(6, 0xD);
        GXSetTevDirect(6);
        GXSetTevOrder(6, 5, 0, 0xFF);
        GXSetTevColorIn(6, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(6, 7, 7, 7, 0);
        GXSetTevSwapMode(6, 0, 0);
        GXSetTevColorOp(6, 0, 0, 3, 1, 0);
        GXSetTevAlphaOp(6, 0, 0, 0, 1, 0);
    } else {
        if ((u8)param4 == 0) {
            /* full setup with stage 0 */
            GXSetTevKAlphaSel(1, 0x1C);
            GXSetNumTevStages(7);

            GXSetTevDirect(0);
            GXSetTevOrder(0, 1, 1, 0xFF);
            GXSetTevColorIn(0, 0xF, 0xF, 0xF, 0xF);
            GXSetTevAlphaIn(0, 4, 7, 7, 6);
            GXSetTevSwapMode(0, 0, 0);
            GXSetTevColorOp(0, 0, 0, 0, 1, 3);
            GXSetTevAlphaOp(0, 1, 0, 3, 1, 3);
            stage_base = 1;
        } else {
            GXSetNumTevStages(6);
        }

        GXSetTevDirect(stage_base);
        GXSetTevOrder(stage_base, 1, 1, 0xFF);
        GXSetTevColorIn(stage_base, 0xF, 0xF, 0xF, 0xF);
        GXSetTevAlphaIn(stage_base, 6, 7, 7, 4);
        GXSetTevSwapMode(stage_base, 0, 0);
        GXSetTevColorOp(stage_base, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(stage_base, 1, 0, 3, 1, 0);

        GXSetTevKColorSel(stage_base + 1, 0xD);
        GXSetTevDirect(stage_base + 1);
        GXSetTevOrder(stage_base + 1, 0, 0, 0xFF);
        GXSetTevColorIn(stage_base + 1, 0xF, 0x8, 0xE, 0xF);
        if ((u8)param4 != 0) {
            GXSetTevAlphaIn(stage_base + 1, 7, 7, 7, 0);
        } else {
            GXSetTevAlphaIn(stage_base + 1, 0, 7, 7, 3);
        }
        GXSetTevSwapMode(stage_base + 1, 0, 0);
        GXSetTevColorOp(stage_base + 1, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(stage_base + 1, 0, 0, 3, 1, 0);

        GXSetTevKColorSel(stage_base + 2, 0xD);
        GXSetTevDirect(stage_base + 2);
        GXSetTevOrder(stage_base + 2, 2, 0, 0xFF);
        GXSetTevColorIn(stage_base + 2, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(stage_base + 2, 7, 7, 7, 0);
        GXSetTevSwapMode(stage_base + 2, 0, 0);
        GXSetTevColorOp(stage_base + 2, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(stage_base + 2, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(stage_base + 3, 0xD);
        GXSetTevDirect(stage_base + 3);
        GXSetTevOrder(stage_base + 3, 3, 0, 0xFF);
        GXSetTevColorIn(stage_base + 3, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(stage_base + 3, 7, 7, 7, 0);
        GXSetTevSwapMode(stage_base + 3, 0, 0);
        GXSetTevColorOp(stage_base + 3, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(stage_base + 3, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(stage_base + 4, 0xD);
        GXSetTevDirect(stage_base + 4);
        GXSetTevOrder(stage_base + 4, 4, 0, 0xFF);
        GXSetTevColorIn(stage_base + 4, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(stage_base + 4, 7, 7, 7, 0);
        GXSetTevSwapMode(stage_base + 4, 0, 0);
        GXSetTevColorOp(stage_base + 4, 0, 0, 0, 0, 0);
        GXSetTevAlphaOp(stage_base + 4, 0, 0, 2, 1, 0);

        GXSetTevKColorSel(stage_base + 5, 0xD);
        GXSetTevDirect(stage_base + 5);
        GXSetTevOrder(stage_base + 5, 5, 0, 0xFF);
        GXSetTevColorIn(stage_base + 5, 0xF, 0x8, 0xE, 0);
        GXSetTevAlphaIn(stage_base + 5, 7, 7, 7, 0);
        GXSetTevSwapMode(stage_base + 5, 0, 0);
        GXSetTevColorOp(stage_base + 5, 0, 0, 3, 1, 0);
        GXSetTevAlphaOp(stage_base + 5, 0, 0, 2, 1, 0);
    }

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD018 != 0 || lbl_803DD014 != 7 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(0, 7, 0);
        lbl_803DD018 = 0;
        lbl_803DD014 = 7;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_8007BD8C
 * EN v1.0 Address: 0x80072048
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007BF08
 * EN v1.1 Size: 1604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007BD8C(int handle1, int handle2)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4;
    extern f32 lbl_803DEF64;
    extern u32 lbl_803DB690, lbl_803DB694, lbl_803DB698;
    extern u32 lbl_803DD01C;
    extern Mtx lbl_80396820;
    extern f32 lbl_8030EA10[3][3];
    extern void* gSHthorntailAnimationInterface;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern void selectReflectionTexture(int);
    extern int fn_8004C248(void);
    extern void selectTexture(int handle, int slot);
    extern void GXSetZMode();
    extern void GXSetZCompLoc(u8);
    Mtx mtx_30;
    GXColor temp;

    selectReflectionTexture(0);
    selectTexture(handle1, 1);
    selectTexture(handle2, 2);

    GXSetTexCoordGen2(1, 1, 4, 0x3C, 0, 0x7D);
    GXLoadTexMtxImm(lbl_80396820, 0x55, 0);
    GXSetTexCoordGen2(0, 0, 0, 0, 0, 0x55);
    PSMTXScale(mtx_30, lbl_803DEF64, lbl_803DEEE4, lbl_803DEEDC);
    GXLoadTexMtxImm(mtx_30, 0x1e, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x1e, 0, 0x7d);
    GXSetChanCtrl(4, 0, 0, 1, 0, 0, 2);

    if (fn_8004C248() != 0) {
        ((u8*)&temp)[0] = ((u8*)&lbl_803DD01C)[0];
        ((u8*)&temp)[1] = ((u8*)&lbl_803DD01C)[1];
        ((u8*)&temp)[2] = ((u8*)&lbl_803DD01C)[2];
    } else {
        f32 dummy;
        (*(void(**)(u8*, u8*, u8*, f32*, f32*, f32*))(*(int*)gSHthorntailAnimationInterface + 0x40))(
            &((u8*)&temp)[0],
            &((u8*)&temp)[1],
            &((u8*)&temp)[2],
            &dummy, &dummy, &dummy);
    }

    *(u32*)&temp = (lbl_803DB690 & 0xFFFFFF00) | (*(u32*)&temp & 0xFFFFFFFF);
    {
        GXColor c0;
        *(u32*)&c0 = lbl_803DB690;
        GXSetTevKColor(0, c0);
    }
    GXSetTevKColorSel(0, 0xC);
    {
        GXColor c1;
        *(u32*)&c1 = lbl_803DB694;
        GXSetTevKColor(1, c1);
    }
    GXSetTevKColorSel(1, 0xD);
    {
        GXColor c2;
        *(u32*)&c2 = lbl_803DB698;
        GXSetTevKColor(2, c2);
    }
    GXSetTevKColorSel(2, 0xE);

    /* Modify temp[0..2] /= 4 */
    ((u8*)&temp)[0] = (u8)((s8)((u8*)&temp)[0] >> 2);
    ((u8*)&temp)[1] = (u8)((s8)((u8*)&temp)[1] >> 2);
    ((u8*)&temp)[2] = (u8)((s8)((u8*)&temp)[2] >> 2);
    GXSetTevColor(1, temp);

    /* Add 0xC0 */
    ((u8*)&temp)[0] = (u8)(((u8*)&temp)[0] + 0xC0);
    ((u8*)&temp)[1] = (u8)(((u8*)&temp)[1] + 0xC0);
    ((u8*)&temp)[2] = (u8)(((u8*)&temp)[2] + 0xC0);
    GXSetTevColor(2, temp);

    GXSetIndTexOrder(0, 1, 1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, lbl_8030EA10, -1);
    GXSetIndTexMtx(2, (f32(*)[3])((u8*)lbl_8030EA10 + 0x18), -1);
    GXSetIndTexMtx(3, (f32(*)[3])((u8*)lbl_8030EA10 + 0x30), -1);
    GXSetTevIndirect(0, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevIndirect(1, 0, 0, 7, 2, 0, 0, 0, 0, 1);
    GXSetTevIndirect(2, 0, 0, 7, 3, 0, 0, 0, 0, 0);
    GXSetNumIndStages(1);
    GXSetNumTexGens(3);
    GXSetNumTevStages(4);
    GXSetNumChans(1);

    GXSetTevOrder(0, 0, 0, 4);
    GXSetTevColorIn(0, 0xF, 0x8, 0xE, 2);
    GXSetTevAlphaIn(0, 7, 7, 7, 5);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevOrder(1, 0, 0, 8);
    GXSetTevColorIn(1, 0xF, 8, 0xE, 0);
    GXSetTevAlphaIn(1, 7, 5, 0, 7);
    GXSetTevSwapMode(1, 0, 0);
    GXSetTevColorOp(1, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 0);

    GXSetTevOrder(2, 0, 0, 0xff);
    GXSetTevColorIn(2, 0xF, 8, 0xE, 0);
    GXSetTevAlphaIn(2, 7, 7, 7, 0);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);

    GXSetTevDirect(3);
    GXSetTevOrder(3, 2, 2, 0xff);
    GXSetTevColorIn(3, 0, 4, 9, 0xF);
    GXSetTevAlphaIn(3, 7, 7, 7, 0);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevColorOp(3, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(3, 0, 0, 0, 1, 0);

    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

/*
 * --INFO--
 *
 * Function: FUN_8007204c
 * EN v1.0 Address: 0x8007204C
 * EN v1.0 Size: 660b
 * EN v1.1 Address: 0x8007C54C
 * EN v1.1 Size: 660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_8007C3D0(u8 flag)
{
    extern f32 lbl_803DEEDC;
    extern f32 gSynthDelayedActionWord0;
    extern void selectReflectionTexture(int);
    f32 mtx[6];

    selectReflectionTexture(1);
    GXSetTexCoordGen2(1, 0, 0, 0x24, 0, 0x7D);
    GXSetTexCoordGen2(0, 1, 4, 0x3C, 0, 0x7D);
    mtx[0] = lbl_803DEEDC;
    mtx[1] = gSynthDelayedActionWord0;
    mtx[2] = lbl_803DEEDC;
    mtx[3] = lbl_803DEEDC;
    mtx[4] = lbl_803DEEDC;
    mtx[5] = gSynthDelayedActionWord0;
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
 * Function: fn_8007C664
 * EN v1.0 Address: 0x800722E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007C7E0
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007C664(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: fn_8007CAF4
 * EN v1.0 Address: 0x800722E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007CC70
 * EN v1.1 Size: 1160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007CAF4(void)
{
}

/*
 * --INFO--
 *
 * Function: fn_8007CF7C
 * EN v1.0 Address: 0x800722E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007D0F8
 * EN v1.1 Size: 1780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007CF7C(void)
{
    extern f32 lbl_803DEEDC, lbl_803DEEE4, lbl_803DEEF0, lbl_803DEEF4;
    extern f32 lbl_803DEF40, lbl_803DEF88;
    extern u8 lbl_803DEF81[8];
    extern u32 lbl_803DB67C;
    extern u32 lbl_803DD01C;
    extern u8 lbl_803DB678;
    extern f32 gSynthDelayedActionWord0;
    extern void* gSHthorntailAnimationInterface;
    extern u8 lbl_803DD012, lbl_803DD018, lbl_803DD01A;
    extern u8 lbl_803DD011, lbl_803DD019;
    extern int lbl_803DD014;
    extern void fn_8006CABC(f32* a, f32* b);
    extern void getTextureFn_8006c5e4(int* out);
    extern void selectReflectionTexture(int);
    extern int fn_8004C248(void);
    extern void selectTexture(int handle, int slot);
    Mtx mtx_cc;
    Mtx mtx_9c;
    Mtx mtx_6c;
    f32 indMtx_54[6];
    f32 indMtx_3c[6];
    f32 indMtx_24[6];
    f32 fA, fB;
    int handle1;
    GXColor temp;

    fn_8006CABC(&fA, &fB);
    selectReflectionTexture(0);
    GXSetTexCoordGen2(0, 0, 0, 0x1e, 0, 0x7d);
    getTextureFn_8006c5e4(&handle1);
    selectTexture(handle1, 1);

    PSMTXScale(mtx_cc, lbl_803DEEE4, lbl_803DEEE4, lbl_803DEEE4);
    mtx_cc[1][3] = fB;
    GXLoadTexMtxImm(mtx_cc, 0x27, 1);
    GXSetTexCoordGen2(1, 1, 4, 0x27, 0, 0x7d);

    indMtx_54[0] = gSynthDelayedActionWord0;
    indMtx_54[1] = lbl_803DEEDC;
    indMtx_54[2] = lbl_803DEEDC;
    indMtx_54[3] = lbl_803DEEDC;
    indMtx_54[4] = gSynthDelayedActionWord0;
    indMtx_54[5] = lbl_803DEEDC;
    GXSetIndTexOrder(0, 1, 1);
    GXSetIndTexCoordScale(0, 0, 0);
    GXSetIndTexMtx(1, (f32(*)[3])indMtx_54, -2);
    GXSetTevIndirect(0, 0, 0, 7, 1, 6, 6, 0, 0, 0);

    PSMTXScale(mtx_9c, lbl_803DEF40, lbl_803DEF40, lbl_803DEF40);
    PSMTXRotRad(mtx_6c, 'z', lbl_803DEEF0);
    PSMTXConcat(mtx_6c, mtx_9c, mtx_9c);
    mtx_9c[1][3] = fA;
    mtx_9c[2][3] = fA;
    GXLoadTexMtxImm(mtx_9c, 0x2a, 1);
    GXSetTexCoordGen2(2, 1, 4, 0x2a, 0, 0x7d);

    indMtx_3c[0] = *(f32*)((u8*)lbl_803DEF81 + 3);
    indMtx_3c[1] = *(f32*)((u8*)lbl_803DEF81 + 3);
    indMtx_3c[2] = lbl_803DEEDC;
    indMtx_3c[3] = lbl_803DEF88;
    indMtx_3c[4] = *(f32*)((u8*)lbl_803DEF81 + 3);
    indMtx_3c[5] = lbl_803DEEDC;
    GXSetIndTexOrder(1, 2, 1);
    GXSetIndTexCoordScale(1, 0, 0);
    GXSetIndTexMtx(2, (f32(*)[3])indMtx_3c, -4);
    GXSetTevIndirect(1, 1, 1, 7, 2, 0, 0, 0, 0, 1);

    /* Color setup */
    if (fn_8004C248() != 0) {
        ((u8*)&lbl_803DB67C)[0] = ((u8*)&lbl_803DD01C)[0];
        ((u8*)&lbl_803DB67C)[1] = ((u8*)&lbl_803DD01C)[1];
        ((u8*)&lbl_803DB67C)[2] = ((u8*)&lbl_803DD01C)[2];
        ((u8*)&lbl_803DB67C)[3] = 0x80;
    } else {
        f32 dummy;
        (*(void(**)(u8*, u8*, u8*, f32*, f32*, f32*))(*(int*)gSHthorntailAnimationInterface + 0x40))(
            (u8*)&lbl_803DB67C,
            (u8*)&lbl_803DB67C + 1,
            (u8*)&lbl_803DB67C + 2,
            &dummy, &dummy, &dummy);
        ((u8*)&lbl_803DB67C)[0] = (u8)((s8)((u8*)&lbl_803DB67C)[0] >> 3);
        ((u8*)&lbl_803DB67C)[1] = (u8)((s8)((u8*)&lbl_803DB67C)[1] >> 3);
        ((u8*)&lbl_803DB67C)[2] = (u8)((s8)((u8*)&lbl_803DB67C)[2] >> 3);
        ((u8*)&lbl_803DB67C)[3] = lbl_803DB678;
    }
    *(u32*)&temp = lbl_803DB67C;
    GXSetTevKColor(0, temp);
    GXSetTevKAlphaSel(1, 0x1c);
    GXSetTevKColorSel(1, 0xc);

    GXSetNumIndStages(2);
    GXSetNumChans(1);
    GXSetNumTexGens(4);
    GXSetNumTevStages(4);

    GXSetTevOrder(0, 0xff, 0xff, 0xff);
    GXSetTevColorIn(0, 0xf, 0xf, 0xf, 0xf);
    GXSetTevAlphaIn(0, 7, 7, 7, 7);
    GXSetTevSwapMode(0, 0, 0);
    GXSetTevColorOp(0, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(0, 0, 0, 0, 1, 0);

    GXSetTevOrder(1, 0, 0, 0xff);
    GXSetTevColorIn(1, 0xe, 0xf, 0xf, 8);
    GXSetTevAlphaIn(1, 7, 7, 7, 6);
    GXSetTevSwapMode(1, 0, 0);
    if (fn_8004C248() != 0) {
        GXSetTevColorOp(1, 0, 0, 3, 1, 1);
    } else {
        GXSetTevColorOp(1, 0, 0, 0, 1, 1);
    }
    GXSetTevAlphaOp(1, 0, 0, 0, 1, 1);

    indMtx_24[0] = lbl_803DEEDC;
    indMtx_24[1] = gSynthDelayedActionWord0;
    indMtx_24[2] = lbl_803DEEDC;
    indMtx_24[3] = lbl_803DEEF4;
    indMtx_24[4] = lbl_803DEEDC;
    indMtx_24[5] = lbl_803DEEDC;
    GXSetIndTexMtx(3, (f32(*)[3])indMtx_24, -5);
    GXSetTevIndirect(2, 0, 0, 7, 2, 6, 6, 0, 0, 0);
    GXSetTevIndirect(3, 1, 0, 7, 3, 0, 0, 0, 0, 1);
    GXSetTexCoordGen2(3, 0, 0, 0x21, 0, 0x7d);

    GXSetTevOrder(2, 0xff, 0xff, 4);
    GXSetTevColorIn(2, 0xf, 0xf, 0xf, 0xf);
    GXSetTevAlphaIn(2, 7, 7, 7, 7);
    GXSetTevSwapMode(2, 0, 0);
    GXSetTevColorOp(2, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(2, 0, 0, 0, 1, 0);

    GXSetTevOrder(3, 3, 0, 4);
    GXSetTevColorIn(3, 8, 2, 3, 0xf);
    GXSetTevAlphaIn(3, 7, 7, 7, 5);
    GXSetTevSwapMode(3, 0, 0);
    GXSetTevColorOp(3, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(3, 0, 0, 0, 1, 0);

    GXSetBlendMode(1, 4, 5, 5);
    if ((u32)lbl_803DD018 != 1 || lbl_803DD014 != 3 ||
        (u32)lbl_803DD012 != 0 || lbl_803DD01A == 0) {
        GXSetZMode(1, 3, 0);
        lbl_803DD018 = 1;
        lbl_803DD014 = 3;
        lbl_803DD012 = 0;
        lbl_803DD01A = 1;
    }
    if ((u32)lbl_803DD011 != 1 || (u32)lbl_803DD019 == 0) {
        GXSetZCompLoc(1);
        lbl_803DD011 = 1;
        lbl_803DD019 = 1;
    }
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

/*
 * --INFO--
 *
 * Function: FUN_800722ec
 * EN v1.0 Address: 0x800722EC
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8007D7EC
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* EN v1.0 Size: 108b - 77% match. MWCC recomputes &lbl_803967C0 for
 * each PSMTXConcat call; target caches it once in r31 (callee-save)
 * and reuses across both calls. Register-allocator preference — not
 * crackable without inline asm. */
#pragma scheduling off
#pragma peephole off
void fn_8007D670(void)
{
    Mtx* mats = &lbl_803967C0;
    Mtx tmp;
    PSMTXConcat(mats[3], mats[0], tmp);
    GXLoadTexMtxImm(tmp, 0x1E, GX_MTX3x4);
    PSMTXConcat(mats[2], mats[0], tmp);
    GXLoadTexMtxImm(tmp, 0x24, GX_MTX3x4);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: OSReport
 * EN v1.0 Address: 0x800723A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007D858
 * EN v1.1 Size: 80b
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
 * Function: fn_8007D72C
 * EN v1.0 Address: 0x8007D72C
 * EN v1.0 Size: 564b
 * EN v1.1 Address: 0x8007D8A8
 * EN v1.1 Size: 564b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Card init / serial-no validation. Mounts slot 0; if the mount comes back
 * "no card filesystem" (-13) it remembers we need to format. On a check
 * error (-6) it runs CARDCheck; if that also returns -6 it formats. On a
 * clean mount (or after the recovery path) it reads the card serial and
 * compares against the cached pair (lbl_803DD048/04C). If the cached pair
 * is zero, or doesn't match the live card, the cache is rejected with a
 * "wrong card" error code (-0x55, lbl_803DB700 = 11). Otherwise CARDFormat
 * if we still owe one, else success: clear the cache, set state 13,
 * unmount, return 1.
 */
#pragma peephole off
#pragma scheduling off
int fn_8007D72C(void)
{
    extern int fn_8007DE0C(int);
    extern void* mmAlloc(int, int, int);
    extern void mm_free(void*);
    extern void fn_8007FDF8(void);
    extern void* lbl_803DD040;
    extern volatile s32 lbl_803DB700;
    extern u32 lbl_803DD048, lbl_803DD04C, lbl_803DD050, lbl_803DD054;
    int need_format;
    int res;
    u64 serial;

    need_format = 0;
    if (fn_8007DE0C(0) == 0) {
        return 0;
    }
    lbl_803DD040 = mmAlloc(0xA000, -1, 0);
    if (lbl_803DD040 == 0) {
        lbl_803DB700 = 8;
        return 0;
    }
    lbl_803DB700 = 0;
    res = CARDMount(0, lbl_803DD040, (void*)fn_8007FDF8);
    if (res == -13) {
        need_format = 1;
    }
    if (res == -6) {
        res = CARDCheck(0);
        if (res == -6) {
            res = CARDFormat(0);
        }
    } else if (res == -13 || res == 0) {
        res = CARDGetSerialNo(0, &serial);
        if (res == 0) {
            u32* serial_words = (u32*)&serial;
            if ((lbl_803DD048 | lbl_803DD04C) == 0 ||
                ((lbl_803DD048 ^ serial_words[0]) | (lbl_803DD04C ^ serial_words[1])) != 0) {
                res = -0x55;
                lbl_803DB700 = 0xB;
            } else if (need_format) {
                res = CARDFormat(0);
            } else {
                CARDUnmount(0);
                mm_free(lbl_803DD040);
                lbl_803DD040 = 0;
                lbl_803DB700 = 0xD;
                return 1;
            }
        }
    }
    CARDUnmount(0);
    mm_free(lbl_803DD040);
    lbl_803DD040 = 0;
    switch (res) {
        case -2:
            lbl_803DB700 = 1;
            break;
        case -3:
            if (lbl_803DB700 != 3) lbl_803DB700 = 2;
            break;
        case -5:
            lbl_803DB700 = 4;
            break;
        case 0:
            lbl_803DB700 = 0xD;
            lbl_803DD04C = 0;
            lbl_803DD048 = 0;
            lbl_803DD054 = 0;
            lbl_803DD050 = 0;
            return 1;
        default:
            return 0;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_800723ac
 * EN v1.0 Address: 0x800723AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8007DADC
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_8007D960(u32 param_1)
{
    u8 v = (u8)param_1;
    lbl_803DD059 = v;
    if (v != 0) {
        return;
    }
    lbl_803DD04C = 0;
    lbl_803DDCC8 = 0;
    lbl_803DD054 = 0;
    lbl_803DDCD0 = 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800723d4
 * EN v1.0 Address: 0x800723D4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8007DB04
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007D988(void)
{
    lbl_803DB700 = 0xd;
}

/*
 * --INFO--
 *
 * Function: FUN_800723e0
 * EN v1.0 Address: 0x800723E0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8007DB10
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
s32 fn_8007D994(void)
{
    return lbl_803DB700;
}

/*
 * --INFO--
 *
 * Function: FUN_800723e8
 * EN v1.0 Address: 0x800723E8
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x8007DB18
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void cardShowLoadingMsg(u8);
extern int fn_8007EB44(int, int, int, int, int, void*);
extern void fn_8007E1AC(int);
extern int fn_8007E6D4(u8, int, void*, void*);
extern int fn_8007E748(int, int, void*);
extern void fn_8007E77C(void);
extern u8 lbl_803DD058;

#pragma scheduling off
#pragma peephole off
int fn_8007D99C(void)
{
    extern void* mmAlloc();
    extern s32 CARDMount();
    extern s32 CARDCheck();
    extern s32 CARDDelete();
    extern void CARDUnmount();
    extern void mm_free();
    extern void fn_8007FDF8();
    extern void* lbl_803DD040;
    extern const char* sMemoryCardFileName;
    extern volatile s32 lbl_803DB700;
    int res;

    lbl_803DD058 = 0;

    do {
        if (fn_8007DE0C(0) == 0) {
            return 0;
        }
        lbl_803DD040 = mmAlloc(0xA000, -1, 0);
        if (lbl_803DD040 == 0) {
            lbl_803DB700 = 8;
            return 0;
        }
        lbl_803DB700 = 0;
        res = CARDMount(0, lbl_803DD040, (void*)fn_8007FDF8);
        if (res == 0 || res == -6) {
            res = CARDCheck(0);
        }
        if (res == 0) {
            res = CARDDelete(0, sMemoryCardFileName);
        }
        CARDUnmount(0);
        mm_free(lbl_803DD040);
        lbl_803DD040 = 0;

        switch (res + 13) {
            case 11: lbl_803DB700 = 1; break;
            case 10:
                if (lbl_803DB700 != 3) lbl_803DB700 = 2;
                break;
            case 0:  lbl_803DB700 = 6; break;
            case 8:  lbl_803DB700 = 4; break;
            case 13:
                lbl_803DB700 = 13;
                return 1;
        }
        fn_8007E1AC(0);
    } while (lbl_803DD058 != 0);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80072564
 * EN v1.0 Address: 0x80072564
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x8007DCA0
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int fn_8007DB24(int a, int b, int c)
{
    int ret;
    lbl_803DD058 = 0;
    cardShowLoadingMsg(1);
    do {
        ret = fn_8007EB44(0, a, 0, b, c, fn_8007E6D4);
        fn_8007E1AC(0);
        if (lbl_803DD058 != 0) {
            cardShowLoadingMsg(1);
        }
    } while (lbl_803DD058 != 0);
    return ret;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80072600
 * EN v1.0 Address: 0x80072600
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x8007DD3C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int fn_8007DBC0(int a)
{
    int ret;
    lbl_803DD058 = 0;
    cardShowLoadingMsg(0);
    do {
        ret = fn_8007EB44(1, 0, 0, a, 0, fn_8007E748);
        fn_8007E1AC(1);
        if (lbl_803DD058 != 0) {
            cardShowLoadingMsg(0);
        }
    } while (lbl_803DD058 != 0);
    return ret;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8007269c
 * EN v1.0 Address: 0x8007269C
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x8007DDD8
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int fn_8007DC5C(int a, int b)
{
    int ret;
    lbl_803DD058 = 0;
    cardShowLoadingMsg(0);
    do {
        ret = fn_8007EB44(1, a, 0, b, 0, fn_8007E77C);
        fn_8007E1AC(0);
        if (lbl_803DD058 != 0) {
            cardShowLoadingMsg(0);
        }
    } while (lbl_803DD058 != 0);
    return ret;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80072744
 * EN v1.0 Address: 0x80072744
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x8007DE80
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
int fn_8007DD04(u8 retry)
{
    extern int fn_8007F83C(int);
    extern void CARDClose(void*);
    extern void CARDUnmount(s32);
    extern void mm_free(void*);
    extern u8 lbl_80396900[];
    extern void* lbl_803DD040;
    extern u8 lbl_803DD05A;
    extern volatile s32 lbl_803DB700;
    int ret;

    if (retry != 0) {
        lbl_803DD058 = 0;
        cardShowLoadingMsg(2);
    }
    do {
        ret = fn_8007F83C(0);
        if (ret != 0) {
            if (lbl_803DD05A != 0) {
                lbl_803DD05A = 0;
                CARDClose(lbl_80396900);
            }
            CARDUnmount(0);
            mm_free(lbl_803DD040);
            lbl_803DD040 = 0;
            lbl_803DB700 = 13;
            if (ret == 2) {
                ret = fn_8007EB44(0, 0, 0, 0, 0, 0);
            }
        }
        if (retry != 0) {
            fn_8007E1AC(0);
        }
        if (lbl_803DD058 != 0) {
            cardShowLoadingMsg(2);
        }
    } while (lbl_803DD058 != 0 && retry != 0);
    return ret;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_8007284c
 * EN v1.0 Address: 0x8007284C
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x8007DF88
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
int fn_8007DE0C(u8 retry)
{
    extern s32 CARDProbeEx(s32 chan, s32* memSize, s32* sectorSize);
    extern volatile s32 lbl_803DB700;
    s32 memSize;
    s32 sectorSize;
    s32 res;

    if (retry != 0) {
        lbl_803DD058 = 0;
    }
    do {
        res = -1;
        while (res == -1) {
            res = CARDProbeEx(0, &memSize, &sectorSize);
        }
        if (res == 0) {
            if (sectorSize == 0x2000) {
                lbl_803DB700 = 13;
                return 1;
            }
            lbl_803DB700 = 7;
        } else if (res == -3) {
            lbl_803DB700 = 2;
        } else if (res == -2) {
            lbl_803DB700 = 1;
        } else {
            lbl_803DB700 = 0;
        }
        if (retry != 0) {
            fn_8007E1AC(0);
        }
    } while (lbl_803DD058 != 0 && retry != 0);
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80072930
 * EN v1.0 Address: 0x80072930
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8007E06C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007DEF0(void)
{
    CARDInit();
}

/*
 * --INFO--
 *
 * Function: FUN_80072950
 * EN v1.0 Address: 0x80072950
 * EN v1.0 Size: 664b
 * EN v1.1 Address: 0x8007E08C
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void fn_8007DF10(u32* buttons, u32* texts, u32* count)
{
    extern u8 lbl_803DD059;
    if (lbl_803DD059 != 0 && (lbl_803DB700 == 7 || lbl_803DB700 == 9)) {
        lbl_803DB700 = 11;
    }
    switch (lbl_803DB700) {
        case 0:
            *count = 0;
            lbl_803DB700 = 13;
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
            lbl_803DB700 = 13;
            return;
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_8007E1AC
 * EN v1.0 Address: 0x8007E1AC
 * EN v1.0 Size: 928b
 * EN v1.1 Address: 0x8007E328
 * EN v1.1 Size: 1144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8007E1AC(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: cardShowLoadingMsg
 * EN v1.0 Address: 0x8007E54C
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x8007E7A0
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Per-frame "blocking" dialog renderer driven by the card-write retry
 * loops in fn_8007DB24/DBC0/DC5C/DD04. Pumps 60 frames of the GX/dialog
 * pipeline; on each frame either lets the active controller draw its own
 * popup (lbl_803DCA4C[0]->vtbl[1]) or falls back to hudDrawColored over the
 * cached prompt id in lbl_803DB708, then routes the OK/Cancel/back text
 * to fn_80016810 based on the dialog kind passed in.
 */
#pragma peephole off
#pragma scheduling off
void cardShowLoadingMsg(u8 kind)
{
    extern void fn_80017434(int);
    extern int padUpdate(void);
    extern void mmFreeTick(int);
    extern void waitNextFrame(void);
    extern int fn_8001FD88(int**);
    extern void** lbl_803DCA4C;
    extern f32 lbl_803DEF98;
    extern f32 lbl_803DEF9C;
    extern void fn_80076510(int, int, f32, f32);
    extern int fn_8003B8F4(int, int, int, int, int, f32);
    extern void fn_8001476C(int, int, int, int);
    extern int lbl_803DB708;
    extern void getLastRenderedFrame(void);
    extern void hudDrawColored(int, int, int, void*, int, int);
    extern void gameTextSetColor(int, int, int, int);
    extern void fn_80016810(int, int, int);
    extern void fn_80019C24(void);
    extern void GXFlush_(int, int);

    int* buttons;
    int saved;
    int frame;
    int j;
    int count;
    void (*draw)(int, int, int);
    u8 mode = kind;

    fn_80017434(0);
    for (frame = 0; frame < 0x3C; frame++) {
        padUpdate();
        mmFreeTick(0);
        waitNextFrame();
        count = fn_8001FD88(&buttons) & 0xFF;
        if ((u32)count != 0) {
            draw = (void (*)(int, int, int))((void**)*lbl_803DCA4C)[1];
            draw(0, 0, 0);
            fn_80076510(0x280, 0x1E0, lbl_803DEF98, lbl_803DEF98);
            for (j = 0; j < count; j++) {
                fn_8003B8F4(buttons[j], 0, 0, 0, 0, lbl_803DEF9C);
            }
            fn_8001476C(0, 0, 0, 0);
        } else {
            saved = lbl_803DB708;
            getLastRenderedFrame();
            hudDrawColored(0, 0, 0, &saved, 0x200, 0);
        }
        gameTextSetColor(0xFF, 0xFF, 0xFF, 0xFF);
        if (mode == 1) {
            fn_80016810(0x323, 0, 0xC8);
        } else if (mode == 2) {
            fn_80016810(0x573, 0, 0xC8);
        } else {
            fn_80016810(0x56C, 0, 0xC8);
        }
        fn_80019C24();
        GXFlush_(1, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_8007E6D4
 * EN v1.0 Address: 0x8007E6D4
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x8007E928
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Card-write callback dispatched through fn_8007EB44 from fn_8007DB24.
 * Stages a per-slot 0x6EC-byte block plus the shared 0xE4-byte trailer
 * into the card-IO buffer (lbl_803DD044), then asks fn_8007E7C0(2) to
 * commit; if that fails it falls back to fn_8007E7C0(1).
 */
#pragma peephole off
#pragma scheduling off
int fn_8007E6D4(u8 slot, int unused, void* src1, void* src2)
{
    extern char* lbl_803DD044;
    extern int fn_8007E7C0(int);
    int ret;
    memcpy(lbl_803DD044 + (u32)slot * 0x6EC + 0xA50, src1, 0x6EC);
    memcpy(lbl_803DD044 + 0x1F14, src2, 0xE4);
    ret = fn_8007E7C0(2);
    if (ret == 0) {
        ret = fn_8007E7C0(1);
    }
    return ret;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_8007E748
 * EN v1.0 Address: 0x8007E748
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8007E99C
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Card-write callback dispatched through fn_8007EB44 from fn_8007DBC0.
 * Copies the 0xE4-byte block at offset 0x1F14 in the card buffer (held in
 * lbl_803DD044) into the caller-supplied destination.
 */
#pragma peephole off
#pragma scheduling off
int fn_8007E748(int param_1, int param_2, void* dst)
{
    extern char* lbl_803DD044;
    memcpy(dst, lbl_803DD044 + 0x1F14, 0xE4);
    return 0;
}
#pragma scheduling reset
#pragma peephole reset
