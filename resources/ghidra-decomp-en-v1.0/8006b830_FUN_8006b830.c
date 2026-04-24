// Function: FUN_8006b830
// Entry: 8006b830
// Size: 304 bytes

void FUN_8006b830(int param_1,int param_2)

{
  int iVar1;
  float fVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 *puVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  
  iVar1 = (param_2 + -1) / 9 + (param_2 + -1 >> 0x1f);
  for (iVar5 = 1; iVar5 <= iVar1 - (iVar1 >> 0x1f); iVar5 = iVar5 * 3 + 1) {
  }
  for (; 0 < iVar5; iVar5 = iVar5 / 3) {
    iVar13 = iVar5 + 1;
    iVar9 = iVar13 * 0xc;
    iVar10 = param_1 + iVar9;
    iVar1 = (param_2 + 1) - iVar13;
    if (iVar13 <= param_2) {
      do {
        uVar6 = *(undefined4 *)(iVar10 + -0xc);
        fVar2 = *(float *)(iVar10 + -8);
        uVar3 = *(undefined4 *)(iVar10 + -4);
        iVar7 = param_1 + iVar9;
        iVar12 = iVar13;
        while ((iVar5 < iVar12 &&
               (iVar11 = param_1 + (iVar12 - iVar5) * 0xc, *(float *)(iVar11 + -8) < fVar2))) {
          uVar4 = *(undefined4 *)(iVar11 + -8);
          *(undefined4 *)(iVar7 + -0xc) = *(undefined4 *)(iVar11 + -0xc);
          *(undefined4 *)(iVar7 + -8) = uVar4;
          *(undefined4 *)(iVar7 + -4) = *(undefined4 *)(iVar11 + -4);
          iVar7 = iVar7 + iVar5 * -0xc;
          iVar12 = iVar12 - iVar5;
        }
        puVar8 = (undefined4 *)(param_1 + iVar12 * 0xc + -0xc);
        *puVar8 = uVar6;
        puVar8[1] = fVar2;
        puVar8[2] = uVar3;
        iVar10 = iVar10 + 0xc;
        iVar13 = iVar13 + 1;
        iVar9 = iVar9 + 0xc;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
  }
  return;
}

