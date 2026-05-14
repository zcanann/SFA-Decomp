#include "ghidra_import.h"
#include "main/tex_dolphin.h"
#include "dolphin/gx.h"
#include "dolphin/mtx.h"
#include "track/intersect.h"

typedef union {
    f64 d;
    struct {
        uint hi;
        uint lo;
    } words;
} SfaIntDouble;

extern void fn_8001DACC();
extern void fn_8001DD48();
extern void fn_8001DD50();
extern void fn_8001E928(undefined *dest, int count, int *out, f32 x1, f32 y1, f32 z1, f32 x2, f32 y2, f32 z2);
extern int Shader_getLayer();
extern void selectTexture();
extern void fn_8004CE0C();
extern void fn_8004D928();
extern void fn_8004D230();
extern void fn_8004DA54();
extern void fn_8004E0FC();
extern void fn_8004E7F8();
extern void fn_8004EECC();
extern void fn_8004EF9C();
extern void fn_8004F080();
extern void fn_8004F2B0();
extern void fn_8004F380();
extern void fn_8004F6D8();
extern void fn_8004FA30();
extern void fn_8004FDA0();
extern void fn_80051528();
extern void fn_80051868();
extern void fn_80051B00();
extern void fn_800523D0();
extern void fn_800524EC();
extern int fn_80054C30();
extern void textureFn_800528bc();
extern void resetLotsOfRenderVars();
extern void fn_8005D3B4();
extern void fn_8006C4E0();
extern void fn_80088730();
extern void fn_8008982C();
extern uint fn_80118294();
extern int isHeavyFogEnabled();

extern f64 lbl_803DEBC0;
extern f32 lbl_803DEBC8;
extern f32 lbl_803DEBCC;
extern f32 displayOffsetH_803DEBFC;
extern f32 CurrTiming_803DEC20;
extern f32 lbl_803DEC24;
extern f32 FBSet_803DEC28;
extern f32 lbl_803DEC2C;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int lbl_803DEBB0;
extern int lbl_803DCE20;
extern int lbl_803DCE28;
extern int lbl_803DCE30;
extern int *lbl_803DCE34;
extern int lbl_803DCE68;
extern int lbl_803DCE6C;
extern int lbl_802C1E40;
extern int lbl_8037E0C0;
extern byte lbl_803DB638;
extern int lbl_803DB63C;
extern int lbl_803DB640;
extern byte lbl_803DB644;
extern int lbl_80382008;
extern int lbl_8038793C;
extern int lbl_803E8444;
extern int lbl_803E8448;
extern undefined4 jumptable_8030E844;

/*
 * --INFO--
 *
 * Function: fn_8005DF5C
 * EN v1.0 Address: 0x8005DF5C
 * EN v1.0 Size: 1004b
 * EN v1.1 Address: 0x8005E0D8
 * EN v1.1 Size: 1004b
 */
#pragma scheduling off
#pragma peephole off
undefined4 fn_8005DF5C(int param_1,float *param_2)
{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  float local_10;
  float local_C;
  float local_8;

  uVar3 = 0;
  iVar2 = 0;
  while( true ) {
    if (uVar3 < 8) {
                    /* WARNING: Could not recover jumptable. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      uVar1 = (**(code **)((int)&jumptable_8030E844 + iVar2))();
      return uVar1;
    }
    local_8 = local_8 * CurrTiming_803DEC20;
    local_C = local_C * CurrTiming_803DEC20;
    local_10 = local_10 * CurrTiming_803DEC20;
    PSMTXMultVec((const float (*)[4])param_2,(Vec *)&local_8,(Vec *)&local_8);
    if (local_10 >= FBSet_803DEC28) break;
    uVar3 = uVar3 + 1;
    iVar2 = iVar2 + 4;
    if (7 < (int)uVar3) {
      return 0;
    }
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8005E348
 * EN v1.0 Address: 0x8005E348
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x8005E4C4
 * EN v1.1 Size: 536b
 */
#pragma scheduling off
#pragma peephole off
void fn_8005E348(undefined4 param_1,undefined4 param_2,int *param_3,Mtx param_4)
{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  f32 fVar7;
  int local_b8;
  undefined4 uStack_b4;
  float local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  float local_a0;
  undefined4 local_9c;
  Mtx afStack_98;
  SfaIntDouble iD2;
  SfaIntDouble iD1;
  float local_28[6];

  uVar5 = param_3[4];
  uVar3 = *(undefined *)(*param_3 + ((int)uVar5 >> 3));
  iVar4 = *param_3 + ((int)uVar5 >> 3);
  uVar1 = *(undefined *)(iVar4 + 1);
  uVar2 = *(undefined *)(iVar4 + 2);
  param_3[4] = uVar5 + 8;
  puVar6 = (undefined4 *)
           (*(int *)((int)param_1 + 0x68) +
           ((uint3)(CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar5 & 7)) & 0xff) * 0x1c);
  uVar5 = *(uint *)((int)param_2 + 0x3c);
  if ((uVar5 & 0x4000) == 0) {
    if ((uVar5 & 0x8000) == 0) {
      if ((uVar5 & 0x10000) == 0) goto LAB_8005E528;
      iVar4 = 0x10;
    }
    else {
      iVar4 = 8;
    }
  }
  else {
    iVar4 = 4;
  }
  fVar7 = lbl_803DEC2C;
  for (uVar5 = 0; (int)uVar5 < iVar4; uVar5 = uVar5 + 1) {
    iD1.words.lo = uVar5 + 1 ^ 0x80000000;
    iD1.words.hi = 0x43300000;
    PSMTXTrans(afStack_98, lbl_803DEBCC,
               fVar7 * (float)(iD1.d - lbl_803DEBC0),
               lbl_803DEBCC);
    PSMTXConcat(param_4,afStack_98,afStack_98);
    GXLoadPosMtxImm(afStack_98,0);
    local_28[0] = *(float*)((int)&lbl_802C1E40 + 0);
    local_28[1] = *(float*)((int)&lbl_802C1E40 + 4);
    local_28[2] = *(float*)((int)&lbl_802C1E40 + 8);
    local_28[3] = *(float*)((int)&lbl_802C1E40 + 12);
    local_28[4] = *(float*)((int)&lbl_802C1E40 + 16);
    local_28[5] = *(float*)((int)&lbl_802C1E40 + 20);
    fn_8006C4E0((int*)&local_b8,(int*)&uStack_b4);
    selectTexture(*(int *)(local_b8 + (uVar5 & 0xff) * 4),1);
    iD2.words.lo = (uVar5 & 0xff) + 1 ^ 0x80000000;
    iD2.words.hi = 0x43300000;
    local_28[0] = (float)(iD2.d - lbl_803DEBC0) *
                  lbl_803DEC24 * displayOffsetH_803DEBFC;
    local_28[4] = local_28[0];
    GXSetIndTexMtx(1,(const float (*)[3])local_28,lbl_803DB644);
    GXCallDisplayList((void *)*(int *)puVar6,(uint)*(ushort *)(puVar6 + 1));
  }
LAB_8005E528:
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8005E560
 * EN v1.0 Address: 0x8005E560
 * EN v1.0 Size: 464b
 * EN v1.1 Address: 0x8005E6DC
 * EN v1.1 Size: 464b
 */
#pragma scheduling off
#pragma peephole off
int fn_8005E560(int param_1,int *param_3,int *param_2)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined uVar4;
  undefined uVar5;
  undefined uVar6;
  volatile int local_18;
  byte local_14;
  byte local_15;
  byte local_16;
  int local_10;
  int local_C;
  int local_8;

  local_18 = lbl_803E8448;
  uVar2 = param_3[4];
  iVar1 = *param_3;
  uVar6 = *(undefined *)(iVar1 + ((int)uVar2 >> 3));
  iVar1 = iVar1 + ((int)uVar2 >> 3);
  uVar4 = *(undefined *)(iVar1 + 1);
  uVar5 = *(undefined *)(iVar1 + 2);
  param_3[4] = uVar2 + 6;
  iVar1 = *(int *)((int)param_1 + 0x64);
  uVar3 = ((uint3)(uVar6 | (uVar4 << 8) | (uVar5 << 16)) >> (uVar2 & 7)) & 0x3f;
  iVar1 = iVar1 + uVar3 * 0x44;
  GXSetTevAlphaIn(0,7,4,5,7);
  selectTexture(*(int *)Shader_getLayer(iVar1,0),0);
  if ((*(uint *)(iVar1 + 0x3c) & 4) != 0) {
    _gxSetFogParams();
    goto LAB_8005E630;
  }
  local_10 = local_18;
  GXSetFog(0,lbl_803DEBCC,lbl_803DEBCC,lbl_803DEBCC,lbl_803DEBCC,*(GXColor*)&local_10);
LAB_8005E630:
  if ((*(uint *)(iVar1 + 0x3c) & 1) == 0) {
    if ((*(uint *)(iVar1 + 0x3c) & 0x40000) == 0) {
      if ((*(uint *)(iVar1 + 0x3c) & 0x800) == 0) {
        if ((*(uint *)(iVar1 + 0x3c) & 0x1000) == 0) goto LAB_8005E6D0;
      }
    }
  }
  local_C = lbl_803DB640;
  GXSetChanAmbColor(0,*(GXColor *)&local_C);
  if ((*(uint *)(iVar1 + 0x3c) & 0x40000) != 0) {
    GXSetChanCtrl(0,0,0,1,0,0,2);
    goto LAB_8005E718;
  }
  GXSetChanCtrl(0,1,0,1,0,0,2);
  goto LAB_8005E718;
LAB_8005E6D0:
  fn_8008982C(0,&local_16,&local_15,&local_14);
  GXSetChanCtrl(0,1,0,1,0,0,2);
  local_8 = *(int*)&local_16;
  GXSetChanAmbColor(0,*(GXColor *)&local_8);
LAB_8005E718:
  return iVar1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8005E730
 * EN v1.0 Address: 0x8005E730
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x8005E8AC
 * EN v1.1 Size: 588b
 */
#pragma scheduling off
#pragma peephole off
void fn_8005E730(undefined4 param_1,undefined4 param_2,int param_3)
{
  int *piVar3;
  SfaIntDouble iD6;
  SfaIntDouble iD5;
  SfaIntDouble iD4;
  SfaIntDouble iD3;
  SfaIntDouble iD2;
  SfaIntDouble iD1;
  f32 fStack_18;
  f32 fStack_14;
  f32 fStack_10;
  int local_C;
  byte local_B;
  byte local_A;
  byte local_9;
  byte local_8;

  fn_8001E928((undefined*)&lbl_803DCE20,2,&local_C,
              (iD1.words.lo = (int)*(short *)((int)param_1 + 6) >> 3 ^ 0x80000000,
               iD1.words.hi = 0x43300000,
               (float)(iD1.d - lbl_803DEBC0) + *(float *)((int)param_2 + 0x18) + playerMapOffsetX),
              (iD2.words.lo = (int)*(short *)((int)param_1 + 8) >> 3 ^ 0x80000000,
               iD2.words.hi = 0x43300000,
               (float)(iD2.d - lbl_803DEBC0) + *(float *)((int)param_2 + 0x28)),
              (iD3.words.lo = (int)*(short *)((int)param_1 + 10) >> 3 ^ 0x80000000,
               iD3.words.hi = 0x43300000,
               (float)(iD3.d - lbl_803DEBC0) + *(float *)((int)param_2 + 0x38) + playerMapOffsetZ),
              (iD4.words.lo = (int)*(short *)((int)param_1 + 0xc) >> 3 ^ 0x80000000,
               iD4.words.hi = 0x43300000,
               (float)(iD4.d - lbl_803DEBC0) + *(float *)((int)param_2 + 0x18) + playerMapOffsetX),
              (iD5.words.lo = (int)*(short *)((int)param_1 + 0xe) >> 3 ^ 0x80000000,
               iD5.words.hi = 0x43300000,
               (float)(iD5.d - lbl_803DEBC0) + *(float *)((int)param_2 + 0x28)),
              (iD6.words.lo = (int)*(short *)((int)param_1 + 0x10) >> 3 ^ 0x80000000,
               iD6.words.hi = 0x43300000,
               (float)(iD6.d - lbl_803DEBC0) + *(float *)((int)param_2 + 0x38) + playerMapOffsetZ));
  resetLotsOfRenderVars();
  fn_8004CE0C(param_3);
  param_3 = 0;
  piVar3 = (int *)&lbl_803DCE20;
  {
    byte *pB = &local_B;
    byte *pA = &local_A;
    byte *p9 = &local_9;
    f32 *p18 = &fStack_18;
    f32 *p14 = &fStack_14;
    for (; param_3 < local_C; piVar3 = piVar3 + 1, param_3 = param_3 + 1) {
      fn_8001DACC(*piVar3,&local_8,p9,pA,pB);
      local_8 = ((int)local_8 >> 1) + ((int)local_8 >> 2);
      local_9 = ((int)local_9 >> 1) + ((int)local_9 >> 2);
      local_A = ((int)local_A >> 1) + ((int)local_A >> 2);
      fn_8001DD50(*piVar3,&fStack_10,p14,p18);
      fn_8001DD48(*piVar3);
      fn_8004FA30(&local_8,&fStack_10);
    }
  }
  textureFn_800528bc();
  GXSetNumChans(1);
  GXSetCullMode(2);
  gxSetZMode_(1,3,0);
  gxSetPeControl_ZCompLoc_(1);
  GXSetBlendMode(1,4,5,5);
  GXSetAlphaCompare(7,0,0,7,0);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8005E97C
 * EN v1.0 Address: 0x8005E97C
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x8005EAF8
 * EN v1.1 Size: 296b
 */
#pragma scheduling off
#pragma peephole off
undefined4
fn_8005E97C(float param_1,float param_2,float param_3,float param_4,float param_5,
            float param_6,float *param_7)
{
  byte bVar1;
  float *pfVar2;
  int i;
  float dVar4;
  float dVar5;
  float dVar6;
  float dVar7;
  float dVar8;
  float dVar9;

  pfVar2 = (float *)&lbl_8038793C;
  for (i = 5; i != 0; i--, pfVar2 = pfVar2 + 5, param_7 = param_7 + 1) {
    bVar1 = *(byte *)(pfVar2 + 4);
    dVar5 = param_1;
    dVar8 = param_2;
    if ((bVar1 & 1) != 0) {
      dVar5 = param_2;
      dVar8 = param_1;
    }
    dVar4 = param_3;
    dVar7 = param_4;
    if ((bVar1 & 2) != 0) {
      dVar4 = param_4;
      dVar7 = param_3;
    }
    dVar6 = param_6;
    dVar9 = param_5;
    if ((bVar1 & 4) != 0) {
      dVar6 = param_5;
      dVar9 = param_6;
    }
    if ((dVar4 * pfVar2[1] + dVar5 * *pfVar2 + dVar9 * pfVar2[2] + pfVar2[3] + *param_7 < lbl_803DEBCC) &&
        (dVar7 * pfVar2[1] + dVar8 * *pfVar2 + dVar6 * pfVar2[2] + pfVar2[3] + *param_7 < lbl_803DEBCC))
      return 0;
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8005EAA4
 * EN v1.0 Address: 0x8005EAA4
 * EN v1.0 Size: 476b
 * EN v1.1 Address: 0x8005EC20
 * EN v1.1 Size: 476b
 */
#pragma scheduling off
#pragma peephole off
undefined4
fn_8005EAA4(int param_1,int param_2,float *param_3,int param_4,float *param_5,float *param_6,
            float *param_7,float *param_8,float *param_9,float *param_10)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  SfaIntDouble iD6;
  SfaIntDouble iD5;
  SfaIntDouble iD4;
  SfaIntDouble iD3;
  SfaIntDouble iD2;
  SfaIntDouble iD1;
  double bias;

  bias = lbl_803DEBC0;
  iD1.words.lo = (int)*(short *)(param_1 + 0xc) >> 3 ^ 0x80000000;
  iD1.words.hi = 0x43300000;
  *param_8 = (float)(iD1.d - bias) + *(float *)(param_2 + 0x18);
  iD2.words.lo = (int)*(short *)(param_1 + 6) >> 3 ^ 0x80000000;
  iD2.words.hi = 0x43300000;
  *param_5 = (float)(iD2.d - bias) + *(float *)(param_2 + 0x18);
  iD3.words.lo = (int)*(short *)(param_1 + 0xe) >> 3 ^ 0x80000000;
  iD3.words.hi = 0x43300000;
  *param_9 = (float)(iD3.d - bias) + *(float *)(param_2 + 0x28);
  iD4.words.lo = (int)*(short *)(param_1 + 8) >> 3 ^ 0x80000000;
  iD4.words.hi = 0x43300000;
  *param_6 = (float)(iD4.d - bias) + *(float *)(param_2 + 0x28);
  iD5.words.lo = (int)*(short *)(param_1 + 0x10) >> 3 ^ 0x80000000;
  iD5.words.hi = 0x43300000;
  *param_10 = (float)(iD5.d - bias) + *(float *)(param_2 + 0x38);
  iD6.words.lo = (int)*(short *)(param_1 + 10) >> 3 ^ 0x80000000;
  iD6.words.hi = 0x43300000;
  *param_7 = (float)(iD6.d - bias) + *(float *)(param_2 + 0x38);
  if (0 < param_4) {
    do {
      bVar1 = *(byte *)(param_3 + 4);
      if ((bVar1 & 1) == 0) {
        fVar2 = *param_5;
        fVar3 = *param_8;
      }
      else {
        fVar2 = *param_8;
        fVar3 = *param_5;
      }
      if ((bVar1 & 2) == 0) {
        fVar4 = *param_6;
        fVar5 = *param_9;
      }
      else {
        fVar4 = *param_9;
        fVar5 = *param_6;
      }
      if ((bVar1 & 4) == 0) {
        fVar6 = *param_7;
        fVar7 = *param_10;
      }
      else {
        fVar6 = *param_10;
        fVar7 = *param_7;
      }
      if ((fVar4 * param_3[1] + fVar2 * *param_3 + fVar6 * param_3[2] + param_3[3] < lbl_803DEBCC)
         && (fVar5 * param_3[1] + fVar3 * *param_3 + fVar7 * param_3[2] + param_3[3] <
             lbl_803DEBCC)) {
        return 0;
      }
      param_3 = param_3 + 5;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8005EC80
 * EN v1.0 Address: 0x8005EC80
 * EN v1.0 Size: 1376b
 * EN v1.1 Address: 0x8005EDFC
 * EN v1.1 Size: 1376b
 */
#pragma scheduling off
#pragma peephole off
void fn_8005EC80(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                int *param_5,undefined4 param_6,float *param_7,undefined4 param_8)
{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int local_30;
  byte local_13;
  byte local_12;
  byte local_11;
  byte local_10;
  byte local_17;
  byte local_16;
  byte local_15;
  byte local_14;
  int local_34;
  int local_38;
  int local_3c;
  float local_1c;
  float local_18;
  float local_20;
  float local_24;
  float local_28;
  float local_2c;
  undefined4 uStack_8;
  undefined4 uStack_9;
  undefined4 uStack_a;
  undefined4 uStack_b;

  /* decode bitstream */
  {
    uint uBits;
    undefined uV1, uV2, uV3;
    int iOff;
    uint uPos;
    uPos = param_5[4];
    uV3 = *(undefined*)(*param_5 + ((int)uPos >> 3));
    iOff = *param_5 + ((int)uPos >> 3);
    uV1 = *(undefined*)(iOff + 1);
    uV2 = *(undefined*)(iOff + 2);
    param_5[4] = uPos + 8;
    iVar1 = *(int *)((int)param_3 + 0x68);
    uBits = (uint3)(CONCAT12(uV2,CONCAT11(uV1,uV3)) >> (uPos & 7)) & 0xff;
    iVar1 = iVar1 + uBits * 0x1c;
  }

  if ((param_4 != 0) && ((*(uint *)((int)param_4 + 0x3c) & 2) != 0)) {
    goto LAB_8005F1C8;
  }

  {
    int local_8[2];
    int local_c[2];
    int local_2c_x, local_28_x, local_24_x, local_20_x;
    int res;
    local_8[0] = (int)&lbl_803E8444 + 0x1c;  /* placeholder for plane list ptr */
    local_c[0] = (int)&lbl_803E8444 + 0x18;
    local_2c_x = 0x2c;
    local_28_x = 0x28;
    local_24_x = 0x24;
    local_20_x = 0x20;
    res = fn_8005EAA4(iVar1,param_2,
                      (float*)((int)&lbl_8037E0C0 + lbl_803DCE30 * 16 + 0xc - lbl_803DCE30 * 16),
                      5,
                      (float*)(local_2c_x + (int)&local_2c_x - local_2c_x),
                      (float*)(local_28_x + (int)&local_28_x - local_28_x),
                      (float*)(local_24_x + (int)&local_24_x - local_24_x),
                      (float*)(local_20_x + (int)&local_20_x - local_20_x),
                      (float*)(local_2c_x),
                      (float*)(local_28_x));
    (void)res;
  }

LAB_8005F1C8:
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8005F1E0
 * EN v1.0 Address: 0x8005F1E0
 * EN v1.0 Size: 888b
 * EN v1.1 Address: 0x8005F35C
 * EN v1.1 Size: 888b
 */
#pragma scheduling off
#pragma peephole off
void fn_8005F1E0(int param_1, int param_2)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined4 local_48;
  Mtx afStack_44;

  local_48 = lbl_803DEBB0;
  if ((*(char *)(param_1 + 0x41) == '\x02') &&
     (iVar1 = Shader_getLayer(param_1,1), (*(byte *)(iVar1 + 4) & 0x7f) == 9)) {
    piVar2 = (int *)Shader_getLayer(param_1,0);
    if (*(char *)((int)piVar2 + 5) == '\0') {
      iVar1 = *piVar2;
    }
    else {
      iVar1 = *piVar2;
      iVar3 = 0;
      iVar6 = 0x50;
      piVar5 = (int *)lbl_803DCE6C;
      do {
        if (((0 < *(short *)(piVar5 + 3)) && (*piVar5 == iVar1)) &&
           (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar5 + 0xe))) {
          iVar1 = fn_80054C30(iVar1,((int *)lbl_803DCE6C)[iVar3 * 4 + 1]);
          break;
        }
        piVar5 = piVar5 + 4;
        iVar3 = iVar3 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    if (*(byte *)((int)piVar2 + 6) == 0xff) {
      pfVar4 = (float *)0x0;
    }
    else {
      iVar3 = (uint)*(byte *)((int)piVar2 + 6) * 0x10;
      PSMTXTrans(afStack_44,
                 *(float *)(lbl_803DCE68 + iVar3) / lbl_803DEBC8,
                 *(float *)(lbl_803DCE68 + iVar3 + 4) / lbl_803DEBC8,
                 lbl_803DEBCC);
      pfVar4 = (float*)afStack_44;
    }
    fn_80051B00(iVar1,pfVar4,0,(char *)&local_48);
    if ((*(uint *)(param_1 + 0x3c) & 0x100) != 0) {
      fn_8004D928();
    }
    piVar2 = (int *)Shader_getLayer(param_1,1);
    if (*(char *)((int)piVar2 + 5) == '\0') {
      iVar1 = *piVar2;
    }
    else {
      iVar1 = *piVar2;
      iVar3 = 0;
      iVar6 = 0x50;
      piVar5 = (int *)lbl_803DCE6C;
      do {
        if (((0 < *(short *)(piVar5 + 3)) && (*piVar5 == iVar1)) &&
           (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar5 + 0xe))) {
          iVar1 = fn_80054C30(iVar1,((int *)lbl_803DCE6C)[iVar3 * 4 + 1]);
          break;
        }
        piVar5 = piVar5 + 4;
        iVar3 = iVar3 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    if (*(byte *)((int)piVar2 + 6) == 0xff) {
      pfVar4 = (float *)0x0;
    }
    else {
      iVar3 = (uint)*(byte *)((int)piVar2 + 6) * 0x10;
      PSMTXTrans(afStack_44,
                 *(float *)(lbl_803DCE68 + iVar3) / lbl_803DEBC8,
                 *(float *)(lbl_803DCE68 + iVar3 + 4) / lbl_803DEBC8,
                 lbl_803DEBCC);
      pfVar4 = (float*)afStack_44;
    }
    fn_80051868(iVar1,pfVar4,9);
    fn_800524EC((char *)&local_48);
  }
  else {
    for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_1 + 0x41); iVar1 = iVar1 + 1) {
      piVar2 = (int *)Shader_getLayer(param_1,iVar1);
      iVar3 = *piVar2;
      if (iVar3 == 0) {
        fn_800523D0();
      }
      else {
        if (*(char *)((int)piVar2 + 5) != '\0') {
          iVar6 = 0;
          iVar7 = 0x50;
          piVar5 = (int *)lbl_803DCE6C;
          do {
            if (((0 < *(short *)(piVar5 + 3)) && (*piVar5 == iVar3)) &&
               (*(char *)((int)piVar2 + 5) == *(char *)((int)piVar5 + 0xe))) {
              iVar3 = fn_80054C30(iVar3,((int *)lbl_803DCE6C)[iVar6 * 4 + 1]);
              break;
            }
            piVar5 = piVar5 + 4;
            iVar6 = iVar6 + 1;
            iVar7 = iVar7 + -1;
          } while (iVar7 != 0);
        }
        if (*(byte *)((int)piVar2 + 6) == 0xff) {
          pfVar4 = (float *)0x0;
        }
        else {
          pfVar4 = (float *)(lbl_803DCE68 + (uint)*(byte *)((int)piVar2 + 6) * 0x10);
          PSMTXTrans(afStack_44,*pfVar4 / lbl_803DEBC8,pfVar4[1] / lbl_803DEBC8,lbl_803DEBCC);
          pfVar4 = (float*)afStack_44;
        }
        if ((*(uint *)(param_1 + 0x3c) & 0x40000) == 0) {
          fn_80051868(iVar3,pfVar4,*(byte *)(piVar2 + 1) & 0x7f);
        }
        else {
          fn_80051528(iVar3,pfVar4);
        }
      }
    }
    if ((*(uint *)(param_1 + 0x3c) & 0x100) != 0) {
      fn_8004D928();
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8005F558
 * EN v1.0 Address: 0x8005F558
 * EN v1.0 Size: 968b
 * EN v1.1 Address: 0x8005F6D4
 * EN v1.1 Size: 968b
 */
#pragma scheduling off
#pragma peephole off
int fn_8005F558(byte param_1,int param_2,int *param_3)
{
  int iVar1;
  uint uVar2;
  undefined uVar3;
  undefined uVar4;
  undefined uVar5;
  uint uPos;
  int local_8;
  int local_c;
  int local_10;
  byte local_14[4];
  byte local_18;
  byte local_19;
  byte local_1a;
  int local_1c;

  local_1c = lbl_803E8444;
  uPos = param_3[4];
  uVar5 = *(undefined *)(*param_3 + ((int)uPos >> 3));
  iVar1 = *param_3 + ((int)uPos >> 3);
  uVar3 = *(undefined *)(iVar1 + 1);
  uVar4 = *(undefined *)(iVar1 + 2);
  param_3[4] = uPos + 6;
  iVar1 = *(int *)((int)param_2 + 0x64);
  uVar2 = (uint3)(CONCAT12(uVar4,CONCAT11(uVar3,uVar5)) >> (uPos & 7)) & 0x3f;
  iVar1 = iVar1 + uVar2 * 0x44;

  if (param_1 == 0) {
    return iVar1;
  }

  if ((*(uint *)(iVar1 + 0x3c) & 4) != 0) {
    _gxSetFogParams();
    goto LAB_8005F608;
  }
  local_10 = local_1c;
  GXSetFog(0,lbl_803DEBCC,lbl_803DEBCC,lbl_803DEBCC,lbl_803DEBCC,*(GXColor*)&local_10);
LAB_8005F608:
  if ((iVar1 != 0) && ((*(uint *)(iVar1 + 0x3c) & 0x80000000) != 0)) {
    return iVar1;
  }
  if ((iVar1 != 0) && ((*(uint *)(iVar1 + 0x3c) & 0x20000) != 0)) {
    int res;
    res = fn_80118294(0,0,0);
    if ((res & 0xff) != 0) {
      return iVar1;
    }
  }
  resetLotsOfRenderVars();
  if ((*(uint *)(iVar1 + 0x3c) & 0x80) != 0) {
    fn_8004DA54(iVar1);
    goto LAB_8005F690;
  }
  fn_8005F1E0(iVar1,(int)0x80);
LAB_8005F690:
  if ((*(uint *)(iVar1 + 0x3c) & 0x20) != 0) {
    int *lPtr = lbl_803DCE34;
    if (lPtr != 0) {
      fn_8004FDA0(lPtr,(int*)&lbl_80382008,&lbl_803DB638);
      goto LAB_8005F6F4;
    }
  }
  if ((*(uint *)(iVar1 + 0x3c) & 0x40) != 0) {
    fn_8004E0FC();
    goto LAB_8005F6F4;
  }
  if (isHeavyFogEnabled()) {
    getColor803dd01c(local_14);
    fn_8004E7F8(local_14);
  }
LAB_8005F6F4:
  if (((*(uint *)(iVar1 + 0x3c) & 0x40000000) != 0) || ((*(uint *)(iVar1 + 0x3c) & 0x20000000) != 0)) {
    GXSetBlendMode(1,4,5,5);
    gxSetZMode_(1,3,0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7,0,0,7,0);
    goto LAB_8005F7FC;
  }
  if ((*(uint *)(iVar1 + 0x3c) & 0x400) != 0) {
    if ((*(uint *)(iVar1 + 0x3c) & 0x80) == 0) {
      GXSetBlendMode(0,1,0,5);
      gxSetZMode_(1,3,1);
      gxSetPeControl_ZCompLoc_(0);
      GXSetAlphaCompare(4,0,0,4,0);
      goto LAB_8005F7FC;
    }
  }
  GXSetBlendMode(0,1,0,5);
  gxSetZMode_(1,3,1);
  gxSetPeControl_ZCompLoc_(1);
  GXSetAlphaCompare(7,0,0,7,0);
LAB_8005F7FC:
  if ((*(uint *)(iVar1 + 0x3c) & 1) == 0) {
    if ((*(uint *)(iVar1 + 0x3c) & 0x40000) == 0) {
      if ((*(uint *)(iVar1 + 0x3c) & 0x800) == 0) {
        if ((*(uint *)(iVar1 + 0x3c) & 0x1000) == 0) goto LAB_8005F89C;
      }
    }
  }
  local_c = lbl_803DB63C;
  GXSetChanAmbColor(0,*(GXColor *)&local_c);
  if ((*(uint *)(iVar1 + 0x3c) & 0x40000) != 0) {
    GXSetChanCtrl(0,0,0,1,0,0,2);
    goto LAB_8005F8E4;
  }
  GXSetChanCtrl(0,1,0,1,0,0,2);
  goto LAB_8005F8E4;
LAB_8005F89C:
  fn_8008982C(0,&local_18,&local_19,&local_1a);
  GXSetChanCtrl(0,1,0,1,0,0,2);
  local_8 = *(int*)&local_18;
  GXSetChanAmbColor(0,*(GXColor *)&local_8);
LAB_8005F8E4:
  if ((*(uint *)(iVar1 + 0x3c) & 0x8) != 0) {
    GXSetCullMode(2);
    goto LAB_8005F908;
  }
  GXSetCullMode(0);
LAB_8005F908:
  return iVar1;
}
#pragma peephole reset
#pragma scheduling reset
