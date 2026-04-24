// Function: FUN_8010fbec
// Entry: 8010fbec
// Size: 128 bytes

void FUN_8010fbec(int param_1,undefined4 param_2,undefined4 *param_3)

{
  if (DAT_803dd5a0 == (undefined4 *)0x0) {
    DAT_803dd5a0 = (undefined4 *)FUN_80023cc8(4,0xf,0);
  }
  if (param_3 == (undefined4 *)0x0) {
    *DAT_803dd5a0 = 0;
  }
  else {
    *DAT_803dd5a0 = *param_3;
  }
  *(undefined2 *)(param_1 + 2) = 0xaf0;
  return;
}

