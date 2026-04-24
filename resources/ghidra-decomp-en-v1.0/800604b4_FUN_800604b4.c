// Function: FUN_800604b4
// Entry: 800604b4
// Size: 216 bytes

void FUN_800604b4(int param_1)

{
  bool bVar1;
  uint uVar2;
  byte bVar3;
  
  if (99 < DAT_803dce06) {
    return;
  }
  bVar3 = 0;
  do {
    if (4 < bVar3) {
      bVar1 = true;
LAB_80060544:
      if ((!bVar1) && (*(char *)(param_1 + 0x2f9) == '\0')) {
        return;
      }
      if (!bVar1) {
        *(undefined *)(param_1 + 0x2fa) = 0xf0;
      }
      uVar2 = (uint)DAT_803dce06;
      DAT_803dce06 = DAT_803dce06 + 1;
      (&DAT_80382038)[uVar2] = param_1;
      return;
    }
    uVar2 = (uint)bVar3;
    if (FLOAT_803debcc +
        (float)(&DAT_80387948)[uVar2 * 5] +
        (float)(&DAT_80387944)[uVar2 * 5] * (*(float *)(param_1 + 0x18) - FLOAT_803dcddc) +
        *(float *)(param_1 + 0x14) * (float)(&DAT_80387940)[uVar2 * 5] +
        (float)(&DAT_8038793c)[uVar2 * 5] * (*(float *)(param_1 + 0x10) - FLOAT_803dcdd8) <
        FLOAT_803debcc) {
      bVar1 = false;
      goto LAB_80060544;
    }
    bVar3 = bVar3 + 1;
  } while( true );
}

