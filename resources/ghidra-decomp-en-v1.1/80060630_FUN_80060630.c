// Function: FUN_80060630
// Entry: 80060630
// Size: 216 bytes

void FUN_80060630(int param_1)

{
  bool bVar1;
  uint uVar2;
  byte bVar3;
  
  if (99 < DAT_803dda86) {
    return;
  }
  bVar3 = 0;
  do {
    if (4 < bVar3) {
      bVar1 = true;
LAB_800606c0:
      if ((!bVar1) && (*(char *)(param_1 + 0x2f9) == '\0')) {
        return;
      }
      if (!bVar1) {
        *(undefined *)(param_1 + 0x2fa) = 0xf0;
      }
      uVar2 = (uint)DAT_803dda86;
      DAT_803dda86 = DAT_803dda86 + 1;
      (&DAT_80382c98)[uVar2] = param_1;
      return;
    }
    uVar2 = (uint)bVar3;
    if (FLOAT_803df84c +
        (float)(&DAT_803885a8)[uVar2 * 5] +
        (float)(&DAT_803885a4)[uVar2 * 5] * (*(float *)(param_1 + 0x18) - FLOAT_803dda5c) +
        *(float *)(param_1 + 0x14) * (float)(&DAT_803885a0)[uVar2 * 5] +
        (float)(&DAT_8038859c)[uVar2 * 5] * (*(float *)(param_1 + 0x10) - FLOAT_803dda58) <
        FLOAT_803df84c) {
      bVar1 = false;
      goto LAB_800606c0;
    }
    bVar3 = bVar3 + 1;
  } while( true );
}

