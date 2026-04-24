// Function: FUN_80106654
// Entry: 80106654
// Size: 504 bytes

void FUN_80106654(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4,
                 int param_5)

{
  int iVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  undefined8 uVar5;
  undefined auStack360 [12];
  float local_15c;
  float local_158;
  float local_154;
  undefined auStack336 [4];
  undefined auStack332 [4];
  undefined auStack328 [16];
  undefined4 local_138;
  undefined4 local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  undefined auStack176 [4];
  undefined auStack172 [4];
  undefined auStack168 [168];
  
  uVar5 = FUN_802860dc();
  FUN_800033a8(auStack360,0,0x144);
  local_138 = *(undefined4 *)(param_5 + 0x30);
  iVar1 = DAT_803dd538 + *(int *)(DAT_803dd538 + 0x1b0) * 4;
  local_15c = *(float *)(iVar1 + 0x14);
  local_158 = *(float *)uVar5;
  local_154 = *(float *)(iVar1 + 0xb4);
  local_c0 = local_15c;
  local_bc = local_158;
  local_b8 = local_154;
  FUN_8000e0a0((double)local_15c,(double)local_158,(double)local_154,auStack176,auStack172,
               auStack168);
  local_c4 = param_4;
  iVar1 = (**(code **)(*DAT_803dca50 + 0x18))();
  (**(code **)(**(int **)(iVar1 + 4) + 0x14))(auStack360,param_4);
  FUN_8000e0a0((double)local_15c,(double)local_158,(double)local_154,auStack336,auStack332,
               auStack328,local_138);
  (**(code **)(**(int **)(iVar1 + 4) + 0x24))
            (auStack360,1,3,DAT_803dd538 + 0x14,DAT_803dd538 + 0x18);
  iVar2 = *(int *)(DAT_803dd538 + 0x1b0) + -3;
  iVar1 = iVar2 * 4;
  for (; iVar2 < *(int *)(DAT_803dd538 + 0x1b0); iVar2 = iVar2 + 1) {
    *(float *)(DAT_803dd538 + iVar1 + 0x1c) = local_15c;
    *(float *)(DAT_803dd538 + iVar1 + 0xbc) = local_154;
    iVar1 = iVar1 + 4;
  }
  dVar3 = (double)FLOAT_803e1740;
  if (dVar3 != (double)*(float *)(DAT_803dd538 + 300)) {
    dVar3 = (double)(float)((double)*(float *)(DAT_803dd538 + 0x128) /
                           (double)*(float *)(DAT_803dd538 + 300));
  }
  dVar4 = (double)FLOAT_803e1744;
  if ((dVar3 <= dVar4) && (dVar4 = dVar3, dVar3 < (double)FLOAT_803e1740)) {
    dVar4 = (double)FLOAT_803e1740;
  }
  dVar3 = (double)FUN_80010dc0(dVar4,DAT_803dd538 + 0x10c,0);
  if (dVar3 < (double)FLOAT_803e1748) {
    dVar3 = (double)FLOAT_803e1748;
  }
  FUN_80010320(dVar3,DAT_803dd538 + 0x120);
  *(undefined4 *)((ulonglong)uVar5 >> 0x20) = *(undefined4 *)(DAT_803dd538 + 0x188);
  *param_3 = *(undefined4 *)(DAT_803dd538 + 400);
  FUN_80286128();
  return;
}

