// Function: FUN_80217364
// Entry: 80217364
// Size: 108 bytes

void FUN_80217364(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 0x194) != 0) {
    FUN_8021fab4();
    FUN_80037cb0(param_1,*(undefined4 *)(iVar1 + 0x194));
  }
  if (*(int *)(iVar1 + 400) != 0) {
    FUN_8002cbc4();
  }
  FUN_80036fa4(param_1,3);
  return;
}

