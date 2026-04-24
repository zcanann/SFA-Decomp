// Function: FUN_801b1908
// Entry: 801b1908
// Size: 140 bytes

void FUN_801b1908(int param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  piVar2[1] = *(int *)(param_2 + 0x14);
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  iVar1 = FUN_8002e1ac(piVar2[1]);
  *piVar2 = iVar1;
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x6a) = 0;
  }
  iVar1 = *(int *)(param_1 + 100);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x810;
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  return;
}

