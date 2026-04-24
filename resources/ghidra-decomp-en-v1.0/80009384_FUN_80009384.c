// Function: FUN_80009384
// Entry: 80009384
// Size: 176 bytes

void FUN_80009384(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if (param_1 < 0) {
    FUN_8007d6dc(s_sampleDirectoryMLoadedCallback_l_802c4fd0);
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
    DAT_803dc7f8 = DAT_803dc7f8 & 0xffffffdf;
    DAT_803dc7f4 = DAT_803dc7f4 | 0x20;
  }
  return;
}

