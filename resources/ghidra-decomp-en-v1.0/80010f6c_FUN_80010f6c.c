// Function: FUN_80010f6c
// Entry: 80010f6c
// Size: 136 bytes

void FUN_80010f6c(int param_1,int param_2,int param_3)

{
  undefined2 uVar1;
  ushort uVar2;
  ushort uVar3;
  ushort *puVar4;
  ushort *puVar5;
  int iVar6;
  
  uVar3 = *(ushort *)(param_1 + param_3 * 4);
  uVar1 = *(undefined2 *)(param_1 + param_3 * 4 + 2);
  while (param_3 <= param_2 >> 1) {
    iVar6 = param_3 * 2;
    if ((iVar6 < param_2) && (puVar5 = (ushort *)(param_1 + param_3 * 8), *puVar5 < puVar5[2])) {
      iVar6 = iVar6 + 1;
    }
    puVar5 = (ushort *)(param_1 + iVar6 * 4);
    uVar2 = *puVar5;
    if (uVar2 <= uVar3) break;
    puVar4 = (ushort *)(param_1 + param_3 * 4);
    *puVar4 = uVar2;
    puVar4[1] = puVar5[1];
    param_3 = iVar6;
  }
  *(ushort *)(param_1 + param_3 * 4) = uVar3;
  *(undefined2 *)(param_1 + param_3 * 4 + 2) = uVar1;
  return;
}

