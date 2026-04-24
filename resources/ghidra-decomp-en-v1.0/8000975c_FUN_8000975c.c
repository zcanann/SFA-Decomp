// Function: FUN_8000975c
// Entry: 8000975c
// Size: 176 bytes

void FUN_8000975c(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if (param_1 < 0) {
    FUN_8007d6dc(s_musicTriggersLoadedCallback_load_802c5094);
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
    DAT_803dc7f8 = DAT_803dc7f8 & 0xfffffffe;
    DAT_803dc7f4 = DAT_803dc7f4 | 1;
  }
  return;
}

