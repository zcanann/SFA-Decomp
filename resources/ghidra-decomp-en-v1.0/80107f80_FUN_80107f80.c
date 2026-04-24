// Function: FUN_80107f80
// Entry: 80107f80
// Size: 136 bytes

void FUN_80107f80(int param_1)

{
  if (DAT_803dd540 == (float *)0x0) {
    DAT_803dd540 = (float *)FUN_80023cc8(0x38,0xf,0);
  }
  FUN_800033a8(DAT_803dd540,0,0x38);
  DAT_803dd540[6] = *(float *)(param_1 + 0xb4);
  *DAT_803dd540 = FLOAT_803e1784;
  DAT_803dd540[5] = FLOAT_803e1788;
  DAT_803dd540[10] = FLOAT_803e17ac;
  return;
}

