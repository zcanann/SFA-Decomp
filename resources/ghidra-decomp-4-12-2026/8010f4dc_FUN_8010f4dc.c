// Function: FUN_8010f4dc
// Entry: 8010f4dc
// Size: 176 bytes

void FUN_8010f4dc(undefined2 *param_1)

{
  if (DAT_803de200 == (float *)0x0) {
    DAT_803de200 = (float *)FUN_80023d8c(0x18,0xf);
  }
  *DAT_803de200 = FLOAT_803e26c0;
  DAT_803de200[1] = FLOAT_803e26a8;
  *(undefined *)(DAT_803de200 + 2) = 0;
  *(undefined *)((int)DAT_803de200 + 9) = 0;
  *(byte *)((int)DAT_803de200 + 0x15) = *(byte *)((int)DAT_803de200 + 0x15) & 0x7f;
  *(undefined2 *)((int)DAT_803de200 + 10) = 1;
  *(undefined *)(DAT_803de200 + 5) = 0;
  DAT_803de200[4] = 0.0;
  *(float *)(param_1 + 0x5a) = FLOAT_803e2700;
  *param_1 = 0x8000;
  return;
}

