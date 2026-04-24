// Function: FUN_80030334
// Entry: 80030334
// Size: 852 bytes

/* WARNING: Removing unreachable block (ram,0x80030668) */

void FUN_80030334(undefined4 param_1,undefined4 param_2,uint param_3)

{
  short sVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  double extraout_f1;
  undefined8 in_f31;
  undefined8 uVar10;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar10 = FUN_802860dc();
  iVar5 = (int)((ulonglong)uVar10 >> 0x20);
  uVar2 = (uint)uVar10;
  dVar9 = (double)FLOAT_803de8e0;
  if ((extraout_f1 <= dVar9) && (dVar9 = extraout_f1, extraout_f1 < (double)FLOAT_803de8f0)) {
    dVar9 = (double)FLOAT_803de8f0;
  }
  *(float *)(iVar5 + 0x98) = (float)dVar9;
  piVar3 = *(int **)(*(int *)(iVar5 + 0x7c) + *(char *)(iVar5 + 0xad) * 4);
  if ((piVar3 != (int *)0x0) && (iVar7 = *piVar3, *(short *)(iVar7 + 0xec) != 0)) {
    iVar6 = piVar3[0xb];
    *(char *)(iVar6 + 99) = (char)param_3;
    *(undefined2 *)(iVar6 + 0x46) = *(undefined2 *)(iVar6 + 0x44);
    *(undefined4 *)(iVar6 + 8) = *(undefined4 *)(iVar6 + 4);
    *(undefined4 *)(iVar6 + 0x18) = *(undefined4 *)(iVar6 + 0x14);
    *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
    *(undefined4 *)(iVar6 + 0x38) = *(undefined4 *)(iVar6 + 0x34);
    *(undefined *)(iVar6 + 0x61) = *(undefined *)(iVar6 + 0x60);
    *(undefined2 *)(iVar6 + 0x4a) = *(undefined2 *)(iVar6 + 0x48);
    *(undefined4 *)(iVar6 + 0x40) = *(undefined4 *)(iVar6 + 0x3c);
    *(undefined2 *)(iVar6 + 0x5c) = *(undefined2 *)(iVar6 + 0x5a);
    *(undefined2 *)(iVar6 + 0x5a) = 0;
    *(undefined2 *)(iVar6 + 100) = 0xffff;
    iVar4 = *(int *)(iVar5 + 0x54);
    if ((iVar4 != 0) && (*(int *)(iVar4 + 8) != 0)) {
      FUN_80035774(iVar5,piVar3,(int)*(short *)(iVar5 + 0x46),iVar4,uVar2,0);
    }
    if (*(int *)(iVar5 + 0x60) != 0) {
      FUN_8002c6c8(iVar5,(int)*(short *)(iVar5 + 0x46),*(int *)(iVar5 + 0x60),uVar2,0);
    }
    sVar1 = *(short *)(iVar5 + 0xa0);
    *(short *)(iVar5 + 0xa0) = (short)uVar10;
    iVar5 = (int)*(short *)(iVar7 + ((int)uVar2 >> 8) * 2 + 0x70) + (uVar2 & 0xff);
    if ((int)(uint)*(ushort *)(iVar7 + 0xec) <= iVar5) {
      iVar5 = *(ushort *)(iVar7 + 0xec) - 1;
    }
    if (iVar5 < 0) {
      iVar5 = 0;
    }
    if ((*(ushort *)(iVar7 + 2) & 0x40) == 0) {
      *(short *)(iVar6 + 0x44) = (short)iVar5;
      iVar5 = *(int *)(*(int *)(iVar7 + 100) + (uint)*(ushort *)(iVar6 + 0x44) * 4);
    }
    else {
      if ((int)(uVar2 - (int)sVar1 | (int)sVar1 - uVar2) < 0) {
        *(char *)(iVar6 + 0x62) = '\x01' - *(char *)(iVar6 + 0x62);
        *(short *)(iVar6 + 0x44) = (short)*(char *)(iVar6 + 0x62);
        if (*(short *)(*(int *)(iVar7 + 0x6c) + iVar5 * 2) == -1) {
          FUN_8007d6dc(s__objanim_c____setBlendMove__WARN_802cad50,*(undefined2 *)(iVar7 + 4));
          iVar5 = 0;
        }
        FUN_80024e7c((int)*(short *)(*(int *)(iVar7 + 0x6c) + iVar5 * 2),(int)(short)iVar5,
                     *(undefined4 *)(iVar6 + (uint)*(ushort *)(iVar6 + 0x44) * 4 + 0x1c),iVar7);
      }
      iVar5 = *(int *)(iVar6 + (uint)*(ushort *)(iVar6 + 0x44) * 4 + 0x1c) + 0x80;
    }
    *(int *)(iVar6 + 0x34) = iVar5 + 6;
    *(byte *)(iVar6 + 0x60) = *(byte *)(iVar5 + 1) & 0xf0;
    *(float *)(iVar6 + 0x14) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(iVar6 + 0x34) + 1)) -
                DOUBLE_803de8e8);
    if (*(char *)(iVar6 + 0x60) == '\0') {
      *(float *)(iVar6 + 0x14) = *(float *)(iVar6 + 0x14) - FLOAT_803de8e0;
    }
    uVar2 = (int)*(char *)(iVar5 + 1) & 0xf;
    if ((uVar2 == 0) || ((param_3 & 0x10) != 0)) {
      *(undefined2 *)(iVar6 + 0x58) = 0;
    }
    else {
      *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
      *(short *)(iVar6 + 0x5e) =
           (short)(int)(FLOAT_803de8f4 /
                       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803de900));
      *(undefined2 *)(iVar6 + 0x58) = 0x4000;
    }
    *(float *)(iVar6 + 0xc) = FLOAT_803de8f0;
    *(float *)(iVar6 + 4) = (float)(dVar9 * (double)*(float *)(iVar6 + 0x14));
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286128(0);
  return;
}

