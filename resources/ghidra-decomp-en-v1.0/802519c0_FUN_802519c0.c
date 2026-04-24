// Function: FUN_802519c0
// Entry: 802519c0
// Size: 60 bytes

undefined4 FUN_802519c0(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = 1;
  if (((&DAT_803ae200)[param_1 * 8] == -1) && (DAT_8032e240 != param_1)) {
    uVar1 = 0;
  }
  return uVar1;
}

