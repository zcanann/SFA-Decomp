// Function: FUN_80252124
// Entry: 80252124
// Size: 60 bytes

undefined4 FUN_80252124(int param_1)

{
  undefined4 uVar1;
  
  uVar1 = 1;
  if (((&DAT_803aee60)[param_1 * 8] == -1) && (DAT_8032ee98 != param_1)) {
    uVar1 = 0;
  }
  return uVar1;
}

