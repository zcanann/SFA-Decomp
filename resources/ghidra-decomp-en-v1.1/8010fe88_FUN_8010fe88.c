// Function: FUN_8010fe88
// Entry: 8010fe88
// Size: 128 bytes

void FUN_8010fe88(int param_1,undefined4 param_2,undefined4 *param_3)

{
  if (DAT_803de218 == (undefined4 *)0x0) {
    DAT_803de218 = (undefined4 *)FUN_80023d8c(4,0xf);
  }
  if (param_3 == (undefined4 *)0x0) {
    *DAT_803de218 = 0;
  }
  else {
    *DAT_803de218 = *param_3;
  }
  *(undefined2 *)(param_1 + 2) = 0xaf0;
  return;
}

