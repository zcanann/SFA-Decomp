// Function: FUN_8015d638
// Entry: 8015d638
// Size: 124 bytes

void FUN_8015d638(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  FUN_8000facc();
  FUN_80036fa4(param_1,3);
  if (*(int *)(param_1 + 200) != 0) {
    FUN_8002cbc4();
    *(undefined4 *)(param_1 + 200) = 0;
  }
  (**(code **)(*DAT_803dcab8 + 0x40))(param_1,uVar1,0x20);
  return;
}

