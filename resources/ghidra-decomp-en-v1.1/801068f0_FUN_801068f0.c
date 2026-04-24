// Function: FUN_801068f0
// Entry: 801068f0
// Size: 504 bytes

void FUN_801068f0(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4,
                 int param_5)

{
  int iVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  undefined8 uVar5;
  undefined auStack_168 [12];
  float local_15c;
  float local_158;
  float local_154;
  float fStack_150;
  float fStack_14c;
  float afStack_148 [4];
  int local_138;
  undefined4 local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float fStack_b0;
  float fStack_ac;
  float afStack_a8 [42];
  
  uVar5 = FUN_80286840();
  FUN_800033a8((int)auStack_168,0,0x144);
  local_138 = *(int *)(param_5 + 0x30);
  iVar1 = DAT_803de1b0 + *(int *)(DAT_803de1b0 + 0x1b0) * 4;
  local_15c = *(float *)(iVar1 + 0x14);
  local_158 = *(float *)uVar5;
  local_154 = *(float *)(iVar1 + 0xb4);
  local_c0 = local_15c;
  local_bc = local_158;
  local_b8 = local_154;
  FUN_8000e0c0((double)local_15c,(double)local_158,(double)local_154,&fStack_b0,&fStack_ac,
               afStack_a8,local_138);
  local_c4 = param_4;
  iVar1 = (**(code **)(*DAT_803dd6d0 + 0x18))();
  (**(code **)(**(int **)(iVar1 + 4) + 0x14))(auStack_168,param_4);
  FUN_8000e0c0((double)local_15c,(double)local_158,(double)local_154,&fStack_150,&fStack_14c,
               afStack_148,local_138);
  (**(code **)(**(int **)(iVar1 + 4) + 0x24))
            (auStack_168,1,3,DAT_803de1b0 + 0x14,DAT_803de1b0 + 0x18);
  iVar2 = *(int *)(DAT_803de1b0 + 0x1b0) + -3;
  iVar1 = iVar2 * 4;
  for (; iVar2 < *(int *)(DAT_803de1b0 + 0x1b0); iVar2 = iVar2 + 1) {
    *(float *)(DAT_803de1b0 + iVar1 + 0x1c) = local_15c;
    *(float *)(DAT_803de1b0 + iVar1 + 0xbc) = local_154;
    iVar1 = iVar1 + 4;
  }
  dVar3 = (double)FLOAT_803e23c0;
  if (dVar3 != (double)*(float *)(DAT_803de1b0 + 300)) {
    dVar3 = (double)(float)((double)*(float *)(DAT_803de1b0 + 0x128) /
                           (double)*(float *)(DAT_803de1b0 + 300));
  }
  dVar4 = (double)FLOAT_803e23c4;
  if ((dVar3 <= dVar4) && (dVar4 = dVar3, dVar3 < (double)FLOAT_803e23c0)) {
    dVar4 = (double)FLOAT_803e23c0;
  }
  dVar3 = FUN_80010de0(dVar4,(float *)(DAT_803de1b0 + 0x10c),(float *)0x0);
  if (dVar3 < (double)FLOAT_803e23c8) {
    dVar3 = (double)FLOAT_803e23c8;
  }
  FUN_80010340(dVar3,(float *)(DAT_803de1b0 + 0x120));
  *(undefined4 *)((ulonglong)uVar5 >> 0x20) = *(undefined4 *)(DAT_803de1b0 + 0x188);
  *param_3 = *(undefined4 *)(DAT_803de1b0 + 400);
  FUN_8028688c();
  return;
}

