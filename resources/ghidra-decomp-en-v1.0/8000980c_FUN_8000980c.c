// Function: FUN_8000980c
// Entry: 8000980c
// Size: 276 bytes

void FUN_8000980c(void)

{
  undefined4 uVar1;
  uint local_18 [4];
  
  if (DAT_803dc800 != 0) {
    uVar1 = FUN_80023834(0);
    FUN_80023800(DAT_803dc800);
    FUN_80023800(DAT_803dc830);
    FUN_80023800(DAT_803dc850);
    FUN_80023834(uVar1);
  }
  DAT_803dc7f8 = DAT_803dc7f8 | 1;
  DAT_803dc800 = FUN_80015964(s__audio_data_Music_bin_802c50bc,local_18,1,FUN_8000975c);
  DAT_803dc804 = local_18[0] >> 4;
  DAT_803dc7f8 = DAT_803dc7f8 | 2;
  DAT_803dc830 = FUN_80015964(s__audio_data_Sfx_bin_802c50d4,local_18,1,FUN_800096ac);
  DAT_803dc834 = local_18[0] >> 5;
  DAT_803dc7f8 = DAT_803dc7f8 | 4;
  DAT_803dc850 = FUN_80015964(s__audio_data_Streams_bin_802c50e8,local_18,1,FUN_80009594);
  DAT_803dc854 = local_18[0] / 0x16;
  return;
}

