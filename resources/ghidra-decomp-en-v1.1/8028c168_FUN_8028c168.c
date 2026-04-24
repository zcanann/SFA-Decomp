// Function: FUN_8028c168
// Entry: 8028c168
// Size: 172 bytes

void FUN_8028c168(int param_1)

{
  int iVar1;
  int local_18;
  undefined4 local_14 [4];
  
  iVar1 = FUN_80287c44(param_1,DAT_80332f5c);
  if (iVar1 == 0) {
    local_18 = 4;
    iVar1 = FUN_8028ce58((int)local_14,DAT_80332f5c,&local_18,0,1);
    if ((iVar1 == 0) && (local_18 != 4)) {
      iVar1 = 0x700;
    }
  }
  if (iVar1 == 0) {
    iVar1 = FUN_80287c44(param_1,local_14[0]);
  }
  if (iVar1 == 0) {
    FUN_80287ca8(param_1,DAT_80332f64._0_2_);
  }
  return;
}

