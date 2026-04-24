// Function: FUN_8028f398
// Entry: 8028f398
// Size: 176 bytes

void FUN_8028f398(int param_1,int param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined *puVar6;
  uint *puVar7;
  uint *puVar8;
  uint *puVar9;
  uint *puVar10;
  
  puVar9 = (uint *)(param_1 + param_3);
  puVar6 = (undefined *)(param_2 + param_3);
  uVar2 = (uint)puVar9 & 3;
  if (uVar2 != 0) {
    param_3 = param_3 - uVar2;
    do {
      puVar6 = puVar6 + -1;
      uVar2 = uVar2 - 1;
      puVar9 = (uint *)((int)puVar9 + -1);
      *(undefined *)puVar9 = *puVar6;
    } while (uVar2 != 0);
  }
  iVar4 = ((uint)puVar6 & 3) * 8;
  iVar5 = ((uint)puVar6 & 3) * -8 + 0x20;
  uVar2 = param_3 >> 3;
  uVar3 = *(uint *)(puVar6 + -((uint)puVar6 & 3));
  puVar8 = (uint *)(puVar6 + -((uint)puVar6 & 3));
  do {
    puVar10 = puVar9;
    puVar7 = puVar8;
    uVar1 = puVar7[-1];
    uVar2 = uVar2 - 1;
    puVar10[-1] = uVar1 << iVar4 | uVar3 >> iVar5;
    puVar8 = puVar7 + -2;
    uVar3 = *puVar8;
    puVar9 = puVar10 + -2;
    *puVar9 = uVar3 << iVar4 | uVar1 >> iVar5;
  } while (uVar2 != 0);
  if ((param_3 & 4) != 0) {
    puVar8 = puVar7 + -3;
    puVar9 = puVar10 + -3;
    *puVar9 = *puVar8 << iVar4 | uVar3 >> iVar5;
  }
  param_3 = param_3 & 3;
  if (param_3 == 0) {
    return;
  }
  puVar6 = (undefined *)((int)puVar8 + ((uint)puVar6 & 3));
  do {
    puVar6 = puVar6 + -1;
    param_3 = param_3 - 1;
    puVar9 = (uint *)((int)puVar9 + -1);
    *(undefined *)puVar9 = *puVar6;
  } while (param_3 != 0);
  return;
}

