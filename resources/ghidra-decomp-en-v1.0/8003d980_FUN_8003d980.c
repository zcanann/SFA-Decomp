// Function: FUN_8003d980
// Entry: 8003d980
// Size: 720 bytes

void FUN_8003d980(int param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  ushort *puVar3;
  int iVar4;
  undefined2 *puVar5;
  int iVar6;
  ushort *puVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  double dVar12;
  undefined2 local_f8;
  undefined2 local_f6;
  undefined2 local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  undefined auStack224 [48];
  undefined auStack176 [12];
  float local_a4;
  float local_94;
  float local_84;
  undefined auStack112 [64];
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  
  piVar10 = *(int **)(param_2 + 0x58);
  uVar2 = FUN_8000f54c();
  FUN_8002b47c(param_1,auStack112,0);
  FUN_80246eb4(uVar2,auStack112,auStack176);
  FUN_8025d0a8(auStack176,DAT_802caed0);
  FUN_8025d124(DAT_802caed0);
  dVar12 = (double)(FLOAT_803dea1c / *(float *)(param_1 + 8));
  FUN_80247318(dVar12,dVar12,auStack224);
  local_a4 = FLOAT_803dea04;
  local_94 = FLOAT_803dea04;
  local_84 = FLOAT_803dea04;
  FUN_80246eb4(auStack176,auStack224,auStack176);
  FUN_8025d160(auStack176,0x1e,0);
  FUN_80072dfc(param_1,param_2,0);
  FUN_802573f8();
  FUN_80256978(9,1);
  FUN_80256978(10,1);
  FUN_80256978(0xd,1);
  iVar9 = piVar10[1];
  iVar8 = piVar10[2];
  FUN_8025889c(0x90,7,*(short *)(piVar10 + 3) * 3);
  iVar4 = 0;
  for (iVar6 = 0; iVar6 < (int)(uint)*(ushort *)(piVar10 + 3); iVar6 = iVar6 + 1) {
    puVar7 = (ushort *)(*piVar10 + iVar4);
    iVar11 = 3;
    puVar3 = puVar7;
    do {
      puVar5 = (undefined2 *)(iVar9 + (uint)*puVar3 * 6);
      write_volatile_2(0xcc008000,*puVar5);
      write_volatile_2(0xcc008000,puVar5[1]);
      write_volatile_2(0xcc008000,puVar5[2]);
      write_volatile_1(DAT_cc008000,*(undefined *)(puVar7 + 3));
      write_volatile_1(DAT_cc008000,*(undefined *)((int)puVar7 + 7));
      write_volatile_1(DAT_cc008000,*(undefined *)(puVar7 + 4));
      puVar5 = (undefined2 *)(iVar8 + (uint)*puVar3 * 4);
      write_volatile_2(0xcc008000,*puVar5);
      write_volatile_2(0xcc008000,puVar5[1]);
      puVar3 = puVar3 + 1;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    iVar4 = iVar4 + 10;
  }
  FUN_8025d124(0);
  iVar4 = FUN_800221a0(0,5);
  if (iVar4 == 0) {
    iVar4 = FUN_800221a0(0,*(short *)((int)piVar10 + 0xe) + -1);
    fVar1 = *(float *)(param_1 + 8);
    uStack44 = (int)*(short *)(iVar9 + iVar4 * 6) >> 8 ^ 0x80000000;
    local_30 = 0x43300000;
    local_ec = fVar1 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dea40) +
               *(float *)(param_1 + 0xc);
    iVar9 = iVar9 + iVar4 * 6;
    uStack36 = (int)*(short *)(iVar9 + 2) >> 8 ^ 0x80000000;
    local_28 = 0x43300000;
    local_e8 = fVar1 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dea40) +
               *(float *)(param_1 + 0x10);
    uStack28 = (int)*(short *)(iVar9 + 4) >> 8 ^ 0x80000000;
    local_20 = 0x43300000;
    local_e4 = fVar1 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dea40) +
               *(float *)(param_1 + 0x14);
    local_f0 = FLOAT_803dea1c;
    local_f8 = 0;
    local_f4 = 0;
    local_f6 = 0;
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x7fd,&local_f8,0x200001,0xffffffff,0);
  }
  return;
}

