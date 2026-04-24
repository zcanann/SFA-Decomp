// Function: FUN_8024f5e8
// Entry: 8024f5e8
// Size: 84 bytes

undefined4 FUN_8024f5e8(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = DAT_803ddfcc;
  DAT_803ddfcc = param_1;
  if (param_1 == 0) {
    FUN_802521a0(&LAB_8024f588);
  }
  else {
    FUN_802520d4(&LAB_8024f588);
  }
  return uVar1;
}

