// Function: FUN_8010f240
// Entry: 8010f240
// Size: 176 bytes

void FUN_8010f240(undefined2 *param_1)

{
  if (DAT_803dd588 == (float *)0x0) {
    DAT_803dd588 = (float *)FUN_80023cc8(0x18,0xf,0);
  }
  *DAT_803dd588 = FLOAT_803e1a40;
  DAT_803dd588[1] = FLOAT_803e1a28;
  *(undefined *)(DAT_803dd588 + 2) = 0;
  *(undefined *)((int)DAT_803dd588 + 9) = 0;
  *(byte *)((int)DAT_803dd588 + 0x15) = *(byte *)((int)DAT_803dd588 + 0x15) & 0x7f;
  *(undefined2 *)((int)DAT_803dd588 + 10) = 1;
  *(undefined *)(DAT_803dd588 + 5) = 0;
  DAT_803dd588[4] = 0.0;
  *(float *)(param_1 + 0x5a) = FLOAT_803e1a80;
  *param_1 = 0x8000;
  return;
}

