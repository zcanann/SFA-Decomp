// Function: FUN_8028ba04
// Entry: 8028ba04
// Size: 172 bytes

void FUN_8028ba04(undefined4 param_1)

{
  int iVar1;
  int local_18;
  undefined4 local_14 [4];
  
  iVar1 = FUN_802874e0(param_1,DAT_803322fc);
  if (iVar1 == 0) {
    local_18 = 4;
    iVar1 = FUN_8028c6f4(local_14,DAT_803322fc,&local_18,0,1);
    if ((iVar1 == 0) && (local_18 != 4)) {
      iVar1 = 0x700;
    }
  }
  if (iVar1 == 0) {
    iVar1 = FUN_802874e0(param_1,local_14[0]);
  }
  if (iVar1 == 0) {
    FUN_80287544(param_1,DAT_80332304);
  }
  return;
}

