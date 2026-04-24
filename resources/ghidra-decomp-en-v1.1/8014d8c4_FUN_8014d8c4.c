// Function: FUN_8014d8c4
// Entry: 8014d8c4
// Size: 192 bytes

void FUN_8014d8c4(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((*(int *)(iVar2 + 0x368) != 0) && (iVar1 = FUN_8001dc28(*(int *)(iVar2 + 0x368)), iVar1 == 0))
  {
    FUN_8001f448(*(uint *)(iVar2 + 0x368));
    *(undefined4 *)(iVar2 + 0x368) = 0;
  }
  *(undefined4 *)(iVar2 + 0x340) = *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x50);
  if (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 1;
  }
  if (((*(int *)(param_1 + 200) != 0) &&
      (iVar1 = *(int *)(*(int *)(param_1 + 200) + 0x54), iVar1 != 0)) &&
     (*(int *)(iVar1 + 0x50) != 0)) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 1;
  }
  if (*(int *)(iVar2 + 0x36c) != 0) {
    FUN_80026d18(*(int *)(iVar2 + 0x36c));
  }
  return;
}

