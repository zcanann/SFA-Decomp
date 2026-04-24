// Function: FUN_80009434
// Entry: 80009434
// Size: 176 bytes

void FUN_80009434(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if (param_1 < 0) {
    FUN_8007d6dc(s_projectDataMLoadedCallback_load_e_802c4ffc);
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
    DAT_803dc7f8 = DAT_803dc7f8 & 0xffffffef;
    DAT_803dc7f4 = DAT_803dc7f4 | 0x10;
  }
  return;
}

