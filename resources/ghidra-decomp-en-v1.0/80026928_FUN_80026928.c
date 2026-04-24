// Function: FUN_80026928
// Entry: 80026928
// Size: 532 bytes

void FUN_80026928(int *param_1,int param_2,int *param_3)

{
  float fVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar8;
  int iVar9;
  
  iVar3 = 0;
  iVar5 = 0;
  for (iVar6 = 0; fVar1 = FLOAT_803de828, iVar6 < param_3[2]; iVar6 = iVar6 + 1) {
    iVar2 = *(int *)(*(int *)param_3[1] + iVar3);
    puVar7 = (undefined4 *)(*param_3 + iVar5);
    iVar8 = iVar2 * 0x1c;
    puVar7[6] = *(undefined4 *)(*(int *)(param_2 + 0x3c) + iVar8 + 4);
    puVar7[7] = *(undefined4 *)(*(int *)(param_2 + 0x3c) + iVar8 + 8);
    puVar7[8] = *(undefined4 *)(*(int *)(param_2 + 0x3c) + iVar8 + 0xc);
    uVar4 = (uint)*(byte *)(*param_1 + 0xf3);
    if (uVar4 == 0) {
      iVar8 = 1;
    }
    else {
      iVar8 = uVar4 + *(byte *)(*param_1 + 0xf4);
    }
    iVar9 = iVar2;
    if (iVar8 <= iVar2) {
      iVar9 = 0;
    }
    *puVar7 = *(undefined4 *)(param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + iVar9 * 0x40 + 0xc);
    uVar4 = (uint)*(byte *)(*param_1 + 0xf3);
    if (uVar4 == 0) {
      iVar8 = 1;
    }
    else {
      iVar8 = uVar4 + *(byte *)(*param_1 + 0xf4);
    }
    iVar9 = iVar2;
    if (iVar8 <= iVar2) {
      iVar9 = 0;
    }
    puVar7[1] = *(undefined4 *)(param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + iVar9 * 0x40 + 0x1c);
    uVar4 = (uint)*(byte *)(*param_1 + 0xf3);
    if (uVar4 == 0) {
      iVar8 = 1;
    }
    else {
      iVar8 = uVar4 + *(byte *)(*param_1 + 0xf4);
    }
    if (iVar8 <= iVar2) {
      iVar2 = 0;
    }
    puVar7[2] = *(undefined4 *)(param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + iVar2 * 0x40 + 0x2c);
    iVar3 = iVar3 + 4;
    iVar5 = iVar5 + 0x54;
  }
  iVar5 = *param_3 + iVar6 * 0x54;
  *(float *)(iVar5 + 0x18) = FLOAT_803de828;
  *(float *)(iVar5 + 0x1c) = fVar1;
  *(float *)(iVar5 + 0x20) = FLOAT_803de850;
  iVar3 = *(int *)(*(int *)param_3[1] + param_3[2] * 4 + -4);
  uVar4 = (uint)*(byte *)(*param_1 + 0xf3);
  if (uVar4 == 0) {
    iVar6 = 1;
  }
  else {
    iVar6 = uVar4 + *(byte *)(*param_1 + 0xf4);
  }
  if (iVar6 <= iVar3) {
    iVar3 = 0;
  }
  FUN_80247494(param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + iVar3 * 0x40,iVar5 + 0x18,iVar5);
  return;
}

