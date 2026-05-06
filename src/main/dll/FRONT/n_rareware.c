#include "ghidra_import.h"
#include "main/dll/FRONT/n_rareware.h"

extern undefined4 FUN_80006c64();
extern undefined4 FUN_80017468();
extern undefined8 FUN_80017484();
extern undefined4 FUN_800709e4();
extern undefined4 FUN_800709e8();

extern undefined4 DAT_803a5098;
extern undefined4 DAT_803a509c;
extern undefined4 DAT_803a50a0;
extern undefined4 DAT_803dd5d0;
extern undefined4 DAT_803dd5e8;
extern undefined4 DAT_803de260;
extern undefined4 DAT_803de264;
extern f64 DOUBLE_803e2968;
extern f32 FLOAT_803e2974;
extern f32 FLOAT_803e2978;

/*
 * --INFO--
 *
 * Function: FUN_801159e4
 * EN v1.0 Address: 0x801159E4
 * EN v1.0 Size: 1120b
 * EN v1.1 Address: 0x80115C80
 * EN v1.1 Size: 880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801159e4(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  undefined3 uVar2;
  undefined uVar4;
  uint uVar3;
  undefined4 extraout_r4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar7;
  undefined4 local_18;
  undefined4 local_14;
  undefined8 local_10;
  undefined8 local_8;
  
  if (DAT_803de264 < 0xf0) {
    if (DAT_803de264 < 0x1e) {
      param_2 = (double)FLOAT_803e2974;
      local_10 = (double)CONCAT44(0x43300000,DAT_803de264);
      iVar1 = (int)((float)(param_2 * (double)(float)(local_10 - DOUBLE_803e2968)) / FLOAT_803e2978)
      ;
      local_8 = (double)(longlong)iVar1;
      uVar4 = (undefined)iVar1;
    }
    else if (DAT_803de264 < 0xd2) {
      uVar4 = 0xff;
    }
    else {
      param_2 = (double)FLOAT_803e2974;
      local_8 = (double)CONCAT44(0x43300000,0xf0 - DAT_803de264);
      iVar1 = (int)((float)(param_2 * (double)(float)(local_8 - DOUBLE_803e2968)) / FLOAT_803e2978);
      local_10 = (double)(longlong)iVar1;
      uVar4 = (undefined)iVar1;
    }
    if (DAT_803dd5e8 == '\0') {
      uVar2 = 0xdc0000;
    }
    else {
      uVar2 = 0x46ff;
    }
    local_18 = CONCAT31(uVar2,uVar4);
    local_14 = local_18;
    in_r7 = 0x100;
    in_r8 = 0;
    FUN_800709e4(DAT_803a5098,0x85,0xaa,&local_14,0x100,0);
  }
  else if (DAT_803de264 < 0x1e0) {
    if (DAT_803de264 < 0x10e) {
      local_8 = (double)CONCAT44(0x43300000,DAT_803de264 - 0xf0);
      uVar3 = (uint)((FLOAT_803e2974 * (float)(local_8 - DOUBLE_803e2968)) / FLOAT_803e2978);
    }
    else if (DAT_803de264 < 0x1c2) {
      uVar3 = 0xff;
    }
    else {
      local_8 = (double)CONCAT44(0x43300000,0x1e0 - DAT_803de264);
      uVar3 = (uint)((FLOAT_803e2974 * (float)(local_8 - DOUBLE_803e2968)) / FLOAT_803e2978);
    }
    local_8 = (double)CONCAT44(0x43300000,(int)(0x280 - (uint)*(ushort *)(DAT_803a509c + 10)) >> 1);
    local_10 = (double)CONCAT44(0x43300000,(int)(0x1e0 - (uint)*(ushort *)(DAT_803a509c + 0xc)) >> 1
                               );
    param_2 = (double)(float)(local_10 - DOUBLE_803e2968);
    FUN_800709e8((double)(float)(local_8 - DOUBLE_803e2968),param_2,DAT_803a509c,uVar3,0x119);
  }
  else if (DAT_803de264 < 600) {
    if (DAT_803de264 < 0x1fe) {
      local_8 = (double)CONCAT44(0x43300000,DAT_803de264 - 0x1e0);
      uVar3 = (uint)((FLOAT_803e2974 * (float)(local_8 - DOUBLE_803e2968)) / FLOAT_803e2978);
    }
    else if (DAT_803de264 < 0x23a) {
      uVar3 = 0xff;
    }
    else {
      local_8 = (double)CONCAT44(0x43300000,600 - DAT_803de264);
      uVar3 = (uint)((FLOAT_803e2974 * (float)(local_8 - DOUBLE_803e2968)) / FLOAT_803e2978);
    }
    local_8 = (double)CONCAT44(0x43300000,(int)(0x280 - (uint)*(ushort *)(DAT_803a50a0 + 10)) >> 1);
    local_10 = (double)CONCAT44(0x43300000,(int)(0x1e0 - (uint)*(ushort *)(DAT_803a50a0 + 0xc)) >> 1
                               );
    param_2 = (double)(float)(local_10 - DOUBLE_803e2968);
    FUN_800709e8((double)(float)(local_8 - DOUBLE_803e2968),param_2,DAT_803a50a0,uVar3,0x119);
  }
  if (DAT_803dd5d0 == '\0') {
    DAT_803de264 = DAT_803de264 + 1;
  }
  else {
    DAT_803de260 = '\x01';
  }
  if (((DAT_803de260 != '\0') && (600 < DAT_803de264)) && (DAT_803dd5d0 == '\0')) {
    uVar5 = 0xff;
    uVar6 = 0xff;
    uVar7 = FUN_80017484(0xff,0xff,0xff,0xff);
    uVar5 = FUN_80017468(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x565,
                         extraout_r4,uVar5,uVar6,in_r7,in_r8,in_r9,in_r10);
    FUN_80006c64(uVar5,0,0x118,300);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void TitleScreenInit_render(void) {}
void TitleScreenInit_frameEnd(void) {}
void TitleScreenInit_release(void) {}
void n_rareware_frameEnd(void) {}
