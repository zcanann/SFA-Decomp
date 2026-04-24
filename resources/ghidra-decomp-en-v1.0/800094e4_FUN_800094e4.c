// Function: FUN_800094e4
// Entry: 800094e4
// Size: 176 bytes

void FUN_800094e4(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if (param_1 < 0) {
    FUN_8007d6dc(s_poolDataMLoadedCallback_load_err_802c5024);
    FUN_80248c64(param_2);
    uVar1 = FUN_80023834(0);
    FUN_80023800(param_2);
    FUN_80023834(uVar1);
  }
  else {
    FUN_80248c64(param_2);
    uVar1 = FUN_80023834(0);
    FUN_80023800(param_2);
    FUN_80023834(uVar1);
    DAT_803dc7f8 = DAT_803dc7f8 & 0xfffffff7;
    DAT_803dc7f4 = DAT_803dc7f4 | 8;
  }
  return;
}

