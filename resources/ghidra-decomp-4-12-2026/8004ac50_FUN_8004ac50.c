// Function: FUN_8004ac50
// Entry: 8004ac50
// Size: 136 bytes

void FUN_8004ac50(int param_1,int param_2,int param_3)

{
  undefined2 uVar1;
  uint *puVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  int iVar6;
  
  uVar5 = *(uint *)(param_1 + param_3 * 8);
  uVar1 = *(undefined2 *)(param_1 + param_3 * 8 + 4);
  while (param_3 <= param_2 >> 1) {
    iVar6 = param_3 * 2;
    if ((iVar6 < param_2) && (puVar4 = (uint *)(param_1 + param_3 * 0x10), *puVar4 < puVar4[2])) {
      iVar6 = iVar6 + 1;
    }
    puVar4 = (uint *)(param_1 + iVar6 * 8);
    uVar3 = *puVar4;
    if (uVar3 <= uVar5) break;
    puVar2 = (uint *)(param_1 + param_3 * 8);
    *puVar2 = uVar3;
    *(undefined2 *)(puVar2 + 1) = *(undefined2 *)(puVar4 + 1);
    param_3 = iVar6;
  }
  *(uint *)(param_1 + param_3 * 8) = uVar5;
  *(undefined2 *)(param_1 + param_3 * 8 + 4) = uVar1;
  return;
}

