// Function: FUN_8008dcb0
// Entry: 8008dcb0
// Size: 160 bytes

void FUN_8008dcb0(undefined4 param_1)

{
  if (DAT_803dd184 != 0) {
    DAT_803dd180 = 2;
    FUN_8005d0bc(param_1,*(uint *)(DAT_803dd184 + 0x24) & 0xff,*(uint *)(DAT_803dd184 + 0x28) & 0xff
                 ,*(uint *)(DAT_803dd184 + 0x2c) & 0xff,0x37);
    if (*(float *)(DAT_803dd184 + 0x14) == *(float *)(DAT_803dd184 + 0x18)) {
      *(float *)(DAT_803dd184 + 0x14) = *(float *)(DAT_803dd184 + 0x14) - FLOAT_803df14c;
    }
    if (*(float *)(DAT_803dd184 + 0x18) < *(float *)(DAT_803dd184 + 0x14)) {
      *(float *)(DAT_803dd184 + 0x14) = *(float *)(DAT_803dd184 + 0x18) - FLOAT_803df14c;
    }
    FUN_80070404((double)*(float *)(DAT_803dd184 + 0x14),(double)*(float *)(DAT_803dd184 + 0x18));
  }
  return;
}

