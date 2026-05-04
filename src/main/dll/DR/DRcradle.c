#include "ghidra_import.h"
#include "main/dll/DR/DRcradle.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017754();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80293130();

extern undefined4* DAT_803dd6d0;
extern f64 DOUBLE_803e6798;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6790;
extern f32 lbl_803E67B8;
extern f32 lbl_803E67E0;
extern f32 lbl_803E6824;
extern f32 lbl_803E683C;
extern f32 lbl_803E6840;
extern f32 lbl_803E687C;
extern f32 lbl_803E688C;
extern f32 lbl_803E6894;
extern f32 lbl_803E6898;
extern f32 lbl_803E68C0;
extern f32 lbl_803E68C4;
extern f32 lbl_803E68C8;
extern f32 lbl_803E68CC;
extern f32 lbl_803E68D0;

/*
 * --INFO--
 *
 * Function: FUN_801ec7a0
 * EN v1.0 Address: 0x801EC7A0
 * EN v1.0 Size: 1424b
 * EN v1.1 Address: 0x801EC7E4
 * EN v1.1 Size: 1524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ec7a0(uint param_1,int param_2)
{
  int iVar1;
  byte bVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  double dVar7;
  undefined4 local_78;
  undefined4 local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60 [2];
  undefined4 local_58;
  uint uStack_54;
  longlong local_50;
  longlong local_48;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined8 local_20;
  undefined8 local_18;
  
  bVar2 = *(byte *)(param_2 + 0x428);
  if ((*(uint *)(param_2 + 0x458) & 0x100) == 0) {
    *(byte *)(param_2 + 0x428) = bVar2 & 0xbf;
  }
  else {
    *(byte *)(param_2 + 0x428) = bVar2 & 0xbf | 0x40;
  }
  if ((*(uint *)(param_2 + 0x458) & 0x200) == 0) {
    *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xef;
  }
  else {
    *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xef | 0x10;
  }
  if (((bVar2 >> 4 & 1) == 0) && ((*(byte *)(param_2 + 0x428) >> 4 & 1) != 0)) {
    FUN_80006824(param_1,0x45f);
  }
  fVar3 = lbl_803E6780;
  if ((*(byte *)(param_2 + 0x428) >> 6 & 1) != 0) {
    fVar3 = *(float *)(param_2 + 0x538);
  }
  fVar3 = lbl_803E68C0 * (fVar3 - *(float *)(param_2 + 0x430));
  fVar6 = lbl_803E68C4;
  if ((lbl_803E68C4 <= fVar3) && (fVar6 = fVar3, lbl_803E6824 < fVar3)) {
    fVar6 = lbl_803E6824;
  }
  *(float *)(param_2 + 0x430) = fVar6 * lbl_803DC074 + *(float *)(param_2 + 0x430);
  fVar6 = lbl_803E6780;
  fVar3 = lbl_803E6780;
  if ((*(byte *)(param_2 + 0x428) >> 4 & 1) != 0) {
    fVar4 = *(float *)(param_2 + 0x53c);
    fVar5 = *(float *)(param_2 + 0x49c);
    if (fVar5 < lbl_803E6780) {
      if ((lbl_803E6780 <= fVar4) && (fVar3 = fVar4, -fVar5 * lbl_803DC078 < fVar4)) {
        fVar3 = -fVar5 * lbl_803DC078;
      }
    }
    else {
      fVar4 = -fVar4;
      fVar3 = -fVar5 * lbl_803DC078;
      if ((fVar3 <= fVar4) && (fVar3 = fVar4, lbl_803E6780 < fVar4)) {
        fVar3 = lbl_803E6780;
      }
    }
  }
  *(float *)(param_2 + 0x4a0) = lbl_803E6780;
  *(float *)(param_2 + 0x4a4) = fVar6;
  *(float *)(param_2 + 0x4a8) = lbl_803DC074 * (*(float *)(param_2 + 0x430) + fVar3);
  FUN_80017778((double)*(float *)(param_2 + 0x4a0),(double)*(float *)(param_2 + 0x4a4),
               (double)*(float *)(param_2 + 0x4a8),(float *)(param_2 + 0x6c),&local_68,&local_64,
               local_60);
  FUN_80017778((double)local_68,(double)local_64,(double)local_60[0],(float *)(param_2 + 300),
               &local_68,&local_64,local_60);
  FUN_80247e94(&local_68,(float *)(param_2 + 0x494),(float *)(param_2 + 0x494));
  *(float *)(param_2 + 0x414) =
       lbl_803DC074 * -*(float *)(param_2 + 0x45c) * *(float *)(param_2 + 0x52c) +
       *(float *)(param_2 + 0x414);
  dVar7 = (double)FUN_80293130((double)*(float *)(param_2 + 0x530),(double)lbl_803DC074);
  *(float *)(param_2 + 0x414) = (float)((double)*(float *)(param_2 + 0x414) * dVar7);
  fVar3 = *(float *)(param_2 + 0x414);
  fVar6 = *(float *)(param_2 + 0x534);
  fVar4 = -fVar6;
  if ((fVar4 <= fVar3) && (fVar4 = fVar3, fVar6 < fVar3)) {
    fVar4 = fVar6;
  }
  *(float *)(param_2 + 0x414) = fVar4;
  uStack_54 = (int)*(short *)(param_2 + 0x40e) ^ 0x80000000;
  local_58 = 0x43300000;
  iVar1 = (int)(*(float *)(param_2 + 0x414) * lbl_803DC074 +
               (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e6798));
  local_50 = (longlong)iVar1;
  *(short *)(param_2 + 0x40e) = (short)iVar1;
  iVar1 = (int)(*(float *)(param_2 + 0x414) * *(float *)(param_2 + 0x550));
  local_48 = (longlong)iVar1;
  uStack_3c = iVar1 - (*(uint *)(param_2 + 0x410) & 0xffff);
  if (0x8000 < (int)uStack_3c) {
    uStack_3c = uStack_3c - 0xffff;
  }
  if ((int)uStack_3c < -0x8000) {
    uStack_3c = uStack_3c + 0xffff;
  }
  uStack_3c = uStack_3c ^ 0x80000000;
  local_40 = 0x43300000;
  uStack_34 = *(uint *)(param_2 + 0x410) ^ 0x80000000;
  local_38 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e6798) *
                *(float *)(param_2 + 0x554) +
               (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e6798));
  local_30 = (longlong)iVar1;
  *(int *)(param_2 + 0x410) = iVar1;
  uStack_24 = (int)*(short *)(param_2 + 0x40e) - (uint)*(ushort *)(param_2 + 0x40c);
  if (0x8000 < (int)uStack_24) {
    uStack_24 = uStack_24 - 0xffff;
  }
  if ((int)uStack_24 < -0x8000) {
    uStack_24 = uStack_24 + 0xffff;
  }
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x40c) ^ 0x80000000);
  *(short *)(param_2 + 0x40c) =
       (short)(int)((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e6798) *
                    *(float *)(param_2 + 0x558) + (float)(local_20 - DOUBLE_803e6798));
  if (*(char *)(param_2 + 0x428) < '\0') {
    *(float *)(param_2 + 0x584) =
         -*(float *)(param_2 + 0x570) * lbl_803DC074 + *(float *)(param_2 + 0x584);
    fVar3 = *(float *)(param_2 + 0x584);
    fVar6 = lbl_803E68C8;
    if ((lbl_803E68C8 <= fVar3) && (fVar6 = fVar3, lbl_803E67E0 < fVar3)) {
      fVar6 = lbl_803E67E0;
    }
    *(float *)(param_2 + 0x584) = fVar6;
    local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 2) ^ 0x80000000);
    *(short *)(param_1 + 2) =
         (short)(int)(*(float *)(param_2 + 0x584) * lbl_803DC074 +
                     (float)(local_18 - DOUBLE_803e6798));
  }
  if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
    local_78 = *(undefined4 *)(param_2 + 0x414);
    local_74 = *(undefined4 *)(param_2 + 0x49c);
    local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 4) ^ 0x80000000);
    local_70 = (float)(local_18 - DOUBLE_803e6798);
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 2) ^ 0x80000000);
    local_6c = (float)(local_20 - DOUBLE_803e6798);
    (**(code **)(*DAT_803dd6d0 + 0x60))(&local_78,0x10);
  }
  fVar3 = *(float *)(param_2 + 0x494);
  fVar6 = *(float *)(param_2 + 0x47c);
  fVar4 = -fVar6;
  if ((fVar4 <= fVar3) && (fVar4 = fVar3, fVar6 < fVar3)) {
    fVar4 = fVar6;
  }
  *(float *)(param_2 + 0x494) = fVar4;
  if ((*(float *)(param_2 + 0x494) < lbl_803E6824) &&
     (lbl_803E683C < *(float *)(param_2 + 0x494))) {
    *(float *)(param_2 + 0x494) = lbl_803E6780;
  }
  fVar3 = *(float *)(param_2 + 0x498);
  fVar6 = -*(float *)(param_2 + 0x480);
  if ((fVar6 <= fVar3) && (fVar6 = fVar3, lbl_803E6784 < fVar3)) {
    fVar6 = lbl_803E6784;
  }
  *(float *)(param_2 + 0x498) = fVar6;
  if ((*(float *)(param_2 + 0x498) < lbl_803E6824) &&
     (lbl_803E683C < *(float *)(param_2 + 0x498))) {
    *(float *)(param_2 + 0x498) = lbl_803E6780;
  }
  fVar3 = *(float *)(param_2 + 0x49c);
  fVar6 = *(float *)(param_2 + 0x484);
  fVar4 = -fVar6;
  if ((fVar4 <= fVar3) && (fVar4 = fVar3, fVar6 < fVar3)) {
    fVar4 = fVar6;
  }
  *(float *)(param_2 + 0x49c) = fVar4;
  if ((*(float *)(param_2 + 0x49c) < lbl_803E6824) &&
     (lbl_803E683C < *(float *)(param_2 + 0x49c))) {
    *(float *)(param_2 + 0x49c) = lbl_803E6780;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ecd30
 * EN v1.0 Address: 0x801ECD30
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801ECDD8
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ecd30(undefined4 param_1,int param_2)
{
  ushort local_28 [4];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  local_1c = lbl_803E6780;
  local_18 = lbl_803E6780;
  local_14 = lbl_803E6780;
  local_20 = lbl_803E6784;
  local_28[0] = *(ushort *)(param_2 + 0x40e);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_80017754((float *)(param_2 + 0x6c),local_28);
  local_28[0] = -*(short *)(param_2 + 0x40e);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_8001774c((float *)(param_2 + 0xac),(int)local_28);
  local_28[0] = *(ushort *)(param_2 + 0x40c);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_80017754((float *)(param_2 + 0xec),local_28);
  local_28[0] = -*(short *)(param_2 + 0x40c);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_8001774c((float *)(param_2 + 300),(int)local_28);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ecdec
 * EN v1.0 Address: 0x801ECDEC
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801ECEA8
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ecdec(undefined4 param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x52c) = lbl_803E68CC;
  *(float *)(param_2 + 0x530) = lbl_803E68D0;
  *(float *)(param_2 + 0x534) = lbl_803E688C;
  fVar1 = lbl_803E6780;
  *(float *)(param_2 + 0x414) = lbl_803E6780;
  *(float *)(param_2 + 0x584) = fVar1;
  *(float *)(param_2 + 0x548) = lbl_803E6894;
  *(float *)(param_2 + 0x54c) = lbl_803E687C;
  *(float *)(param_2 + 0x540) = lbl_803E67B8;
  *(float *)(param_2 + 0x544) = lbl_803E6790;
  *(float *)(param_2 + 0x558) = lbl_803E6840;
  *(float *)(param_2 + 0x56c) = lbl_803E6898;
  *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0x7f;
  *(float *)(param_2 + 0x430) = fVar1;
  *(undefined4 *)(param_2 + 0x464) = *(undefined4 *)(param_2 + 0x470);
  *(undefined4 *)(param_2 + 0x47c) = *(undefined4 *)(param_2 + 0x470);
  *(undefined4 *)(param_2 + 0x468) = *(undefined4 *)(param_2 + 0x474);
  *(undefined4 *)(param_2 + 0x480) = *(undefined4 *)(param_2 + 0x474);
  *(undefined4 *)(param_2 + 0x46c) = *(undefined4 *)(param_2 + 0x478);
  *(undefined4 *)(param_2 + 0x484) = *(undefined4 *)(param_2 + 0x478);
  *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xbf;
  *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xef;
  *(undefined4 *)(param_2 + 0x42c) = 0;
  *(float *)(param_2 + 0x3e4) = fVar1;
  *(float *)(param_2 + 0x3e0) = lbl_803E6784;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_801ECA5C(void) {}
void fn_801ECA60(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_801ECDD0(void) { return 0x2; }
int fn_801ECDD8(void) { return 0x0; }
int fn_801ECE30(void) { return 0x59c; }
int fn_801ECE38(void) { return 0x3; }

/* Pattern wrappers. */
u8 fn_801ECE00(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x420); }

/* 16b chained patterns. */
s32 fn_801ECBC4(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x422); }
s32 fn_801ECD88(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x421); }
