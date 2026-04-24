// Function: FUN_80037ad4
// Entry: 80037ad4
// Size: 40 bytes

undefined4 FUN_80037ad4(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if ((param_1 != 0) && ((*(ushort *)(param_1 + 0xb0) & 0x40) == 0)) {
    uVar1 = 1;
  }
  return uVar1;
}

