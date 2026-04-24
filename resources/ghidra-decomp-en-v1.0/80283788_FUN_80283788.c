// Function: FUN_80283788
// Entry: 80283788
// Size: 44 bytes

void FUN_80283788(int param_1,uint param_2)

{
  int iVar1;
  
  iVar1 = DAT_803de344 + param_1 * 0xf4;
  *(undefined2 *)(iVar1 + 0xcc) = *(undefined2 *)(&DAT_803dc618 + (param_2 & 0xff) * 2);
  *(uint *)(iVar1 + 0x24) = *(uint *)(iVar1 + 0x24) | 0x100;
  return;
}

