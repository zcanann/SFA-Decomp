// Function: FUN_801ee668
// Entry: 801ee668
// Size: 1024 bytes

/* WARNING: Removing unreachable block (ram,0x801eea44) */

void FUN_801ee668(short *param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  short sVar5;
  uint uVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack152 [27];
  char local_7d;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  longlong local_68;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  longlong local_50;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar2 = *(int *)(param_2 + 0x74) * -6000;
  iVar3 = iVar2 / 0x46 + (iVar2 >> 0x1f);
  iVar2 = *(int *)(param_2 + 0x70) * -12000;
  iVar4 = iVar2 / 0x46 + (iVar2 >> 0x1f);
  uStack116 = *(int *)(param_2 + 0x70) << 3 ^ 0x80000000;
  local_78 = 0x43300000;
  uStack108 = (int)*(short *)(param_2 + 0x2c) ^ 0x80000000;
  local_70 = 0x43300000;
  iVar2 = (int)-(((float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e5ca0) / FLOAT_803e5c98
                 ) * FLOAT_803db414 -
                (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e5ca0));
  local_68 = (longlong)iVar2;
  *(short *)(param_2 + 0x2c) = (short)iVar2;
  *(short *)(param_2 + 0x2c) =
       *(short *)(param_2 + 0x2c) -
       (short)((int)((int)*(short *)(param_2 + 0x2c) * (uint)DAT_803db410) >> 5);
  uStack92 = (iVar3 - (iVar3 >> 0x1f)) - ((int)param_1[1] & 0xffffU);
  if (0x8000 < (int)uStack92) {
    uStack92 = uStack92 - 0xffff;
  }
  if ((int)uStack92 < -0x8000) {
    uStack92 = uStack92 + 0xffff;
  }
  uStack92 = uStack92 ^ 0x80000000;
  local_60 = 0x43300000;
  uStack84 = (int)param_1[1] ^ 0x80000000;
  local_58 = 0x43300000;
  iVar2 = (int)(FLOAT_803e5ca8 *
                (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e5ca0) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e5ca0));
  local_50 = (longlong)iVar2;
  param_1[1] = (short)iVar2;
  uStack68 = (iVar4 - (iVar4 >> 0x1f)) - ((int)*(short *)(param_2 + 0x2e) & 0xffffU);
  if (0x8000 < (int)uStack68) {
    uStack68 = uStack68 - 0xffff;
  }
  if ((int)uStack68 < -0x8000) {
    uStack68 = uStack68 + 0xffff;
  }
  uStack68 = uStack68 ^ 0x80000000;
  local_48 = 0x43300000;
  uStack60 = (int)*(short *)(param_2 + 0x2e) ^ 0x80000000;
  local_40 = 0x43300000;
  iVar2 = (int)(FLOAT_803e5ca8 *
                (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e5ca0) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e5ca0));
  local_38 = (longlong)iVar2;
  *(short *)(param_2 + 0x2e) = (short)iVar2;
  sVar5 = param_1[1];
  if (sVar5 < -8000) {
    sVar5 = -8000;
  }
  else if (8000 < sVar5) {
    sVar5 = 8000;
  }
  param_1[1] = sVar5;
  sVar5 = *(short *)(param_2 + 0x2e);
  if (sVar5 < -13000) {
    sVar5 = -13000;
  }
  else if (13000 < sVar5) {
    sVar5 = 13000;
  }
  *(short *)(param_2 + 0x2e) = sVar5;
  *param_1 = *(short *)(param_2 + 0x2c) + 0x4000;
  param_1[2] = *(short *)(param_2 + 0x2e);
  local_7d = '\0';
  uStack44 = (int)param_1[1] ^ 0x80000000;
  local_30 = 0x43300000;
  dVar8 = (double)FLOAT_803e5cac;
  dVar9 = (double)(float)((double)FLOAT_803e5cb0 *
                          (double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e5ca0) +
                         dVar8);
  if (dVar9 <= (double)FLOAT_803e5cb4) {
    if (param_1[0x50] != 0x100) {
      FUN_80030334((double)FLOAT_803e5c70,param_1,0x100,0);
    }
  }
  else {
    dVar8 = dVar9;
    if (param_1[0x50] != 5) {
      FUN_80030334((double)FLOAT_803e5c70,param_1,5,0);
      dVar8 = dVar9;
    }
  }
  FUN_8002fa48(dVar8,(double)FLOAT_803db414,param_1,auStack152);
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_2 + 0x4c);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 0x50);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_2 + 0x54);
  if (local_7d != '\0') {
    FUN_8000bb18(0,0x126);
  }
  bVar1 = false;
  if (*(char *)(param_2 + 0x80) < '\0') {
    uVar6 = FUN_80014ee8(0);
    if ((uVar6 & 0x100) == 0) {
      *(byte *)(param_2 + 0x80) = *(byte *)(param_2 + 0x80) & 0x7f;
    }
    else if (*(char *)(param_2 + 100) == '\0') {
      bVar1 = true;
      *(undefined *)(param_2 + 100) = 0x28;
    }
  }
  else {
    uVar6 = FUN_80014ee8(0);
    if (((uVar6 & 0x100) != 0) &&
       (*(byte *)(param_2 + 0x80) = *(byte *)(param_2 + 0x80) & 0x7f | 0x80,
       *(char *)(param_2 + 100) < '\x14')) {
      bVar1 = true;
      *(undefined *)(param_2 + 100) = 0x28;
    }
  }
  if (bVar1) {
    FUN_801ee0c0(param_1,param_2);
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return;
}

