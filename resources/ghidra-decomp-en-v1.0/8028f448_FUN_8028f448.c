// Function: FUN_8028f448
// Entry: 8028f448
// Size: 196 bytes

void FUN_8028f448(int param_1,int param_2,uint param_3)

{
  uint uVar1;
  undefined *puVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  uint *puVar7;
  undefined *puVar8;
  uint *puVar9;
  uint *puVar10;
  uint uVar11;
  int iVar12;
  
  puVar8 = (undefined *)(param_2 + -1);
  uVar5 = -param_1 & 3;
  puVar2 = (undefined *)(param_1 + -1);
  if (uVar5 != 0) {
    param_3 = param_3 - uVar5;
    do {
      puVar8 = puVar8 + 1;
      uVar5 = uVar5 - 1;
      puVar2 = puVar2 + 1;
      *puVar2 = *puVar8;
    } while (uVar5 != 0);
  }
  uVar1 = (uint)(puVar8 + 1) & 3;
  uVar5 = param_3 >> 3;
  uVar11 = (int)(puVar8 + 1) * 8 & 0x18;
  uVar4 = *(uint *)(puVar8 + (1 - uVar1));
  iVar12 = 0x20 - uVar11;
  puVar7 = (uint *)(puVar2 + -3);
  puVar10 = (uint *)(puVar8 + (1 - uVar1));
  do {
    puVar9 = puVar10;
    puVar6 = puVar7;
    uVar3 = puVar9[1];
    uVar5 = uVar5 - 1;
    puVar6[1] = uVar4 << uVar11 | uVar3 >> iVar12;
    puVar10 = puVar9 + 2;
    uVar4 = *puVar10;
    puVar7 = puVar6 + 2;
    *puVar7 = uVar3 << uVar11 | uVar4 >> iVar12;
  } while (uVar5 != 0);
  if ((param_3 & 4) != 0) {
    puVar10 = puVar9 + 3;
    puVar7 = puVar6 + 3;
    *puVar7 = uVar4 << uVar11 | *puVar10 >> iVar12;
  }
  param_3 = param_3 & 3;
  puVar8 = (undefined *)((int)puVar7 + 3);
  if (param_3 == 0) {
    return;
  }
  puVar2 = (undefined *)((int)puVar10 + (3 - (4 - uVar1)));
  do {
    puVar2 = puVar2 + 1;
    param_3 = param_3 - 1;
    puVar8 = puVar8 + 1;
    *puVar8 = *puVar2;
  } while (param_3 != 0);
  return;
}

