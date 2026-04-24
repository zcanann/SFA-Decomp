// Function: FUN_80024524
// Entry: 80024524
// Size: 380 bytes

void FUN_80024524(int param_1,int param_2,int param_3)

{
  uint uVar1;
  float fVar2;
  byte bVar3;
  double dVar4;
  undefined *puVar5;
  undefined *puVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  
  dVar4 = DOUBLE_803de820;
  iVar9 = 0;
  iVar7 = param_2;
  iVar8 = param_2;
  if (0 < param_3) {
    do {
      if ((*(ushort *)(param_1 + 2) & 0x40) == 0) {
        puVar5 = (undefined *)
                 (*(int *)(param_1 + 0x68) +
                 (uint)*(ushort *)(iVar7 + 0x44) *
                 ((*(byte *)(param_1 + 0xf3) - 1 & 0xfffffff8) + 8));
        puVar6 = *(undefined **)(*(int *)(param_1 + 100) + (uint)*(ushort *)(iVar7 + 0x44) * 4);
      }
      else {
        puVar5 = *(undefined **)(param_2 + (uint)*(ushort *)(iVar7 + 0x44) * 4 + 0x1c);
        puVar6 = puVar5 + 0x80;
      }
      bVar3 = *(byte *)(*(int *)(iVar8 + 0x34) + 2);
      iVar11 = 0;
      for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(param_1 + 0xf3); iVar10 = iVar10 + 1) {
        *(undefined *)(iVar9 + *(int *)(param_1 + 0x3c) + iVar11 + 2) = *puVar5;
        iVar11 = iVar11 + 0x1c;
        puVar5 = puVar5 + 1;
      }
      uVar1 = (uint)*(float *)(iVar8 + 4);
      fVar2 = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - dVar4);
      if (fVar2 == *(float *)(iVar8 + 4)) {
        *(undefined2 *)(iVar7 + 0x4c) = 0;
      }
      else {
        *(ushort *)(iVar7 + 0x4c) = (ushort)bVar3;
      }
      if ((*(char *)(param_2 + iVar9 + 0x60) != '\0') &&
         (fVar2 == *(float *)(iVar8 + 0x14) - FLOAT_803de818)) {
        *(ushort *)(iVar7 + 0x4c) = -(ushort)bVar3 * (short)uVar1;
      }
      *(undefined **)(iVar8 + 0x2c) = puVar6 + (int)*(short *)(puVar6 + 2) + bVar3 * uVar1;
      iVar7 = iVar7 + 2;
      iVar8 = iVar8 + 4;
      iVar9 = iVar9 + 1;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
  }
  return;
}

