// Function: FUN_800269ec
// Entry: 800269ec
// Size: 532 bytes

void FUN_800269ec(int *param_1,int param_2,int *param_3)

{
  float fVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  float *pfVar6;
  int iVar7;
  undefined4 *puVar8;
  int iVar9;
  int iVar10;
  
  iVar3 = 0;
  iVar5 = 0;
  for (iVar7 = 0; fVar1 = FLOAT_803df4a8, iVar7 < param_3[2]; iVar7 = iVar7 + 1) {
    iVar2 = *(int *)(*(int *)param_3[1] + iVar3);
    puVar8 = (undefined4 *)(*param_3 + iVar5);
    iVar9 = iVar2 * 0x1c;
    puVar8[6] = *(undefined4 *)(*(int *)(param_2 + 0x3c) + iVar9 + 4);
    puVar8[7] = *(undefined4 *)(*(int *)(param_2 + 0x3c) + iVar9 + 8);
    puVar8[8] = *(undefined4 *)(*(int *)(param_2 + 0x3c) + iVar9 + 0xc);
    uVar4 = (uint)*(byte *)(*param_1 + 0xf3);
    if (uVar4 == 0) {
      iVar9 = 1;
    }
    else {
      iVar9 = uVar4 + *(byte *)(*param_1 + 0xf4);
    }
    iVar10 = iVar2;
    if (iVar9 <= iVar2) {
      iVar10 = 0;
    }
    *puVar8 = *(undefined4 *)(param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + iVar10 * 0x40 + 0xc);
    uVar4 = (uint)*(byte *)(*param_1 + 0xf3);
    if (uVar4 == 0) {
      iVar9 = 1;
    }
    else {
      iVar9 = uVar4 + *(byte *)(*param_1 + 0xf4);
    }
    iVar10 = iVar2;
    if (iVar9 <= iVar2) {
      iVar10 = 0;
    }
    puVar8[1] = *(undefined4 *)(param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + iVar10 * 0x40 + 0x1c);
    uVar4 = (uint)*(byte *)(*param_1 + 0xf3);
    if (uVar4 == 0) {
      iVar9 = 1;
    }
    else {
      iVar9 = uVar4 + *(byte *)(*param_1 + 0xf4);
    }
    if (iVar9 <= iVar2) {
      iVar2 = 0;
    }
    puVar8[2] = *(undefined4 *)(param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + iVar2 * 0x40 + 0x2c);
    iVar3 = iVar3 + 4;
    iVar5 = iVar5 + 0x54;
  }
  pfVar6 = (float *)(*param_3 + iVar7 * 0x54);
  pfVar6[6] = FLOAT_803df4a8;
  pfVar6[7] = fVar1;
  pfVar6[8] = FLOAT_803df4d0;
  iVar3 = *(int *)(*(int *)param_3[1] + param_3[2] * 4 + -4);
  uVar4 = (uint)*(byte *)(*param_1 + 0xf3);
  if (uVar4 == 0) {
    iVar5 = 1;
  }
  else {
    iVar5 = uVar4 + *(byte *)(*param_1 + 0xf4);
  }
  if (iVar5 <= iVar3) {
    iVar3 = 0;
  }
  FUN_80247bf8((float *)(param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + iVar3 * 0x40),pfVar6 + 6,
               pfVar6);
  return;
}

