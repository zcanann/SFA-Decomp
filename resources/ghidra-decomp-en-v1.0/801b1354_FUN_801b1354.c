// Function: FUN_801b1354
// Entry: 801b1354
// Size: 140 bytes

void FUN_801b1354(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar3 = *(undefined4 **)(param_1 + 0xb8);
  puVar3[1] = *(undefined4 *)(param_2 + 0x14);
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  uVar1 = FUN_8002e0b4(puVar3[1]);
  *puVar3 = uVar1;
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x6a) = 0;
  }
  iVar2 = *(int *)(param_1 + 100);
  if (iVar2 != 0) {
    *(uint *)(iVar2 + 0x30) = *(uint *)(iVar2 + 0x30) | 0x810;
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  return;
}

