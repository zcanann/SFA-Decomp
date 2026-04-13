// Function: FUN_80201c24
// Entry: 80201c24
// Size: 440 bytes

void FUN_80201c24(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar7;
  undefined4 uVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar10;
  undefined4 local_38;
  undefined4 local_34;
  int local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  uVar10 = FUN_8028683c();
  uVar3 = (uint)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  iVar9 = *(int *)(*(int *)(uVar3 + 0xb8) + 0x40c);
  uVar8 = *(undefined4 *)(iVar9 + 0x30);
  *(byte *)(iVar9 + 0x14) = *(byte *)(iVar9 + 0x14) | 2;
  fVar2 = FLOAT_803e6f40;
  *(float *)(iVar6 + 0x280) = FLOAT_803e6f40;
  *(float *)(iVar6 + 0x284) = fVar2;
  uVar10 = extraout_f1;
  if ((*(int *)(iVar6 + 0x2d0) == 0) ||
     (iVar4 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x2d0) + 0x68) + 0x20))(),
     uVar10 = extraout_f1_00, iVar4 == 0)) {
    *(undefined *)(iVar9 + 0x34) = 1;
  }
  if ((*(int *)(iVar9 + 0x18) == 0) && (sVar1 = *(short *)(iVar9 + 0x1c), sVar1 != -1)) {
    local_24 = *(undefined4 *)(iVar9 + 0x30);
    local_28 = *(undefined4 *)(iVar9 + 0x2c);
    psVar7 = *(short **)(iVar9 + 0x24);
    local_2c = *(undefined4 *)(iVar9 + 0x28);
    uVar5 = FUN_800138e4(psVar7);
    if (uVar5 == 0) {
      uVar10 = FUN_80013978(psVar7,(uint)&local_2c);
    }
    psVar7 = *(short **)(iVar9 + 0x24);
    local_38 = 7;
    local_34 = 0;
    local_30 = (int)sVar1;
    uVar5 = FUN_800138e4(psVar7);
    if (uVar5 == 0) {
      uVar10 = FUN_80013978(psVar7,(uint)&local_38);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
    *(undefined2 *)(iVar9 + 0x1c) = 0xffff;
  }
  if ((*(uint *)(iVar6 + 0x314) & 0x200) != 0) {
    *(undefined4 *)(iVar9 + 0x18) = *(undefined4 *)(iVar6 + 0x2d0);
    *(short *)(iVar9 + 0x1c) = (short)uVar8;
    *(undefined4 *)(iVar9 + 0x2c) = 0;
    in_r6 = 0x12;
    FUN_800379bc(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(iVar9 + 0x18),0x11,uVar3,0x12,in_r7,in_r8,in_r9,in_r10);
    FUN_8000bb38(uVar3,0x1eb);
  }
  *(undefined *)(iVar6 + 0x34d) = 0x12;
  if (*(char *)(iVar6 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar3,0x10,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar6 + 0x346) = 0;
  }
  if (*(char *)(iVar6 + 0x346) != '\0') {
    *(undefined *)(iVar9 + 0x34) = 1;
  }
  FUN_80286888();
  return;
}

