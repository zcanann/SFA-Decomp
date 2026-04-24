// Function: FUN_8000a264
// Entry: 8000a264
// Size: 128 bytes

void FUN_8000a264(int param_1,undefined4 param_2)

{
  if (param_1 == -1) {
    FUN_8007d6dc(s_MIDIWADLoadedCallback_load_error_802c5d40);
    FUN_80248c64(param_2);
    FUN_80023800(param_2);
  }
  else {
    FUN_80248c64(param_2);
    FUN_80023800(param_2);
    DAT_803dc7f8 = DAT_803dc7f8 & 0xfffff7ff;
    DAT_803dc7f4 = DAT_803dc7f4 | 0x800;
  }
  return;
}

