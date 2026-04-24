// Function: FUN_80160cd4
// Entry: 80160cd4
// Size: 116 bytes

void FUN_80160cd4(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,3);
  if (*(int *)(param_1 + 200) != 0) {
    FUN_8002cbc4();
    *(undefined4 *)(param_1 + 200) = 0;
  }
  (**(code **)(*DAT_803dcab8 + 0x40))(param_1,uVar1,1);
  return;
}

