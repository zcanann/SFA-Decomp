// Function: FUN_8004b31c
// Entry: 8004b31c
// Size: 632 bytes

undefined4 FUN_8004b31c(int *param_1,int param_2,int param_3,int param_4,byte param_5)

{
  undefined2 uVar1;
  short sVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  int iVar9;
  
  iVar3 = 0;
  *(undefined2 *)((int)param_1 + 0x22) = 0;
  *(undefined2 *)(param_1 + 8) = 0;
  iVar6 = 0;
  iVar7 = 0;
  iVar9 = 0x1f;
  do {
    *(undefined4 *)(param_1[1] + iVar6) = 0;
    *(undefined *)(*param_1 + iVar7 + 0xe) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 8) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x1e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x10) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x2e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x18) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x3e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x20) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x4e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x28) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x5e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x30) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x6e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x38) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x7e) = 0;
    iVar6 = iVar6 + 0x40;
    iVar7 = iVar7 + 0x80;
    iVar3 = iVar3 + 8;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  iVar6 = iVar3 * 8;
  iVar7 = iVar3 * 0x10;
  iVar9 = 0xfe - iVar3;
  if (iVar3 < 0xfe) {
    do {
      *(undefined4 *)(param_1[1] + iVar6) = 0;
      *(undefined *)(*param_1 + iVar7 + 0xe) = 0;
      iVar6 = iVar6 + 8;
      iVar7 = iVar7 + 0x10;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  param_1[6] = param_2;
  param_1[3] = param_3;
  param_1[4] = param_4;
  *(byte *)(param_1 + 10) = param_5 & 1;
  param_1[9] = 10000;
  sVar2 = *(short *)(param_1 + 8);
  if (sVar2 == 0xfe) {
    piVar8 = (int *)0x0;
  }
  else {
    *(short *)(param_1 + 8) = sVar2 + 1;
    piVar8 = (int *)(*param_1 + sVar2 * 0x10);
    *piVar8 = param_2;
    piVar8[2] = 0;
    *(undefined *)(piVar8 + 3) = 0xff;
    FUN_800216d0(*piVar8 + 8,param_1[3]);
    iVar3 = FUN_80285fb4();
    piVar8[1] = iVar3;
  }
  iVar6 = piVar8[1];
  iVar3 = piVar8[2];
  puVar4 = (undefined4 *)param_1[1];
  sVar2 = *(short *)((int)param_1 + 0x22) + 1;
  *(short *)((int)param_1 + 0x22) = sVar2;
  *(short *)(puVar4 + sVar2 * 2 + 1) = *(short *)(param_1 + 8) + -1;
  puVar4[*(short *)((int)param_1 + 0x22) * 2] = -1 - (iVar6 + iVar3);
  iVar3 = (int)*(short *)((int)param_1 + 0x22);
  uVar5 = puVar4[iVar3 * 2];
  uVar1 = *(undefined2 *)(puVar4 + iVar3 * 2 + 1);
  *puVar4 = 0xffffffff;
  while (iVar6 = iVar3 >> 1, (uint)puVar4[iVar6 * 2] < uVar5) {
    *(undefined2 *)(puVar4 + iVar3 * 2 + 1) = *(undefined2 *)(puVar4 + iVar6 * 2 + 1);
    puVar4[iVar3 * 2] = puVar4[iVar6 * 2];
    iVar3 = iVar6;
  }
  puVar4[iVar3 * 2] = uVar5;
  *(undefined2 *)(puVar4 + iVar3 * 2 + 1) = uVar1;
  return 0;
}

