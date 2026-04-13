// Function: FUN_801bee40
// Entry: 801bee40
// Size: 108 bytes

void FUN_801bee40(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  FUN_8003709c(param_1,3);
  (**(code **)(*DAT_803dd738 + 0x40))(param_1,uVar1,1);
  if (DAT_803de810 != 0) {
    FUN_8001f448(DAT_803de810);
  }
  return;
}

