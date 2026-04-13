// Function: FUN_801eeca0
// Entry: 801eeca0
// Size: 1024 bytes

/* WARNING: Removing unreachable block (ram,0x801ef07c) */
/* WARNING: Removing unreachable block (ram,0x801eecb0) */
/* WARNING: Removing unreachable block (ram,0x801eefc0) */

void FUN_801eeca0(ushort *param_1,int param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  ushort uVar4;
  short sVar5;
  uint uVar6;
  double dVar7;
  undefined8 uVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double dVar11;
  
  iVar2 = *(int *)(param_2 + 0x74) * -6000;
  iVar2 = iVar2 / 0x46 + (iVar2 >> 0x1f);
  iVar2 = iVar2 - (iVar2 >> 0x1f);
  iVar3 = *(int *)(param_2 + 0x70) * -12000;
  iVar3 = iVar3 / 0x46 + (iVar3 >> 0x1f);
  *(short *)(param_2 + 0x2c) =
       (short)(int)-(((float)((double)CONCAT44(0x43300000,*(int *)(param_2 + 0x70) << 3 ^ 0x80000000
                                              ) - DOUBLE_803e6938) / FLOAT_803e6930) *
                     FLOAT_803dc074 -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x2c) ^ 0x80000000
                                            ) - DOUBLE_803e6938));
  *(short *)(param_2 + 0x2c) =
       *(short *)(param_2 + 0x2c) -
       (short)((int)((int)*(short *)(param_2 + 0x2c) * (uint)DAT_803dc070) >> 5);
  uVar6 = iVar2 - (uint)param_1[1];
  if (0x8000 < (int)uVar6) {
    uVar6 = uVar6 - 0xffff;
  }
  if ((int)uVar6 < -0x8000) {
    uVar6 = uVar6 + 0xffff;
  }
  param_1[1] = (ushort)(int)(FLOAT_803e6940 *
                             (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) -
                                    DOUBLE_803e6938) * FLOAT_803dc074 +
                            (float)((double)CONCAT44(0x43300000,(int)(short)param_1[1] ^ 0x80000000)
                                   - DOUBLE_803e6938));
  uVar6 = (iVar3 - (iVar3 >> 0x1f)) - (uint)*(ushort *)(param_2 + 0x2e);
  if (0x8000 < (int)uVar6) {
    uVar6 = uVar6 - 0xffff;
  }
  if ((int)uVar6 < -0x8000) {
    uVar6 = uVar6 + 0xffff;
  }
  dVar10 = (double)FLOAT_803e6940;
  *(short *)(param_2 + 0x2e) =
       (short)(int)(dVar10 * (double)((float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) -
                                             DOUBLE_803e6938) * FLOAT_803dc074) +
                   (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(param_2 + 0x2e) ^ 0x80000000) -
                                  DOUBLE_803e6938));
  uVar4 = param_1[1];
  if ((short)uVar4 < -8000) {
    uVar4 = 0xe0c0;
  }
  else if (8000 < (short)uVar4) {
    uVar4 = 8000;
  }
  param_1[1] = uVar4;
  sVar5 = *(short *)(param_2 + 0x2e);
  if (sVar5 < -13000) {
    sVar5 = -13000;
  }
  else if (13000 < sVar5) {
    sVar5 = 13000;
  }
  *(short *)(param_2 + 0x2e) = sVar5;
  *param_1 = *(short *)(param_2 + 0x2c) + 0x4000;
  param_1[2] = *(ushort *)(param_2 + 0x2e);
  dVar9 = (double)FLOAT_803e6948;
  dVar7 = (double)FLOAT_803e6944;
  dVar11 = (double)(float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,
                                                                    (int)(short)param_1[1] ^
                                                                    0x80000000) - DOUBLE_803e6938) +
                          dVar7);
  if (dVar11 <= (double)FLOAT_803e694c) {
    if (param_1[0x50] != 0x100) {
      FUN_8003042c((double)FLOAT_803e6908,dVar9,dVar10,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,0x100,0
                   ,iVar2,param_5,param_6,param_7,param_8);
    }
  }
  else {
    dVar7 = dVar11;
    if (param_1[0x50] != 5) {
      FUN_8003042c((double)FLOAT_803e6908,dVar9,dVar10,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,5,0,
                   iVar2,param_5,param_6,param_7,param_8);
      dVar7 = dVar11;
    }
  }
  dVar9 = (double)FLOAT_803dc074;
  uVar8 = FUN_8002fb40(dVar7,dVar9);
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_2 + 0x4c);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 0x50);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_2 + 0x54);
  bVar1 = false;
  if (*(char *)(param_2 + 0x80) < '\0') {
    uVar6 = FUN_80014f14(0);
    if ((uVar6 & 0x100) == 0) {
      *(byte *)(param_2 + 0x80) = *(byte *)(param_2 + 0x80) & 0x7f;
    }
    else if (*(char *)(param_2 + 100) == '\0') {
      bVar1 = true;
      *(undefined *)(param_2 + 100) = 0x28;
    }
  }
  else {
    uVar6 = FUN_80014f14(0);
    if (((uVar6 & 0x100) != 0) &&
       (*(byte *)(param_2 + 0x80) = *(byte *)(param_2 + 0x80) & 0x7f | 0x80,
       *(char *)(param_2 + 100) < '\x14')) {
      bVar1 = true;
      *(undefined *)(param_2 + 100) = 0x28;
    }
  }
  if (bVar1) {
    FUN_801ee6f8(uVar8,dVar9,dVar10,in_f4,in_f5,in_f6,in_f7,in_f8,param_1);
  }
  return;
}

