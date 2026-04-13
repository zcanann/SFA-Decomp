// Function: FUN_80282630
// Entry: 80282630
// Size: 284 bytes

void FUN_80282630(uint param_1,int param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar1 = param_1 & 0xff;
  uVar2 = *(uint *)(param_2 + 0xf4) & 0xff;
  uVar3 = *(uint *)(param_3 + 0xf4) & 0xff;
  if (uVar1 < 0x40) {
    uVar1 = param_1 & 0x1f;
    *(undefined *)(uVar2 * 0x86 + uVar1 + -0x7fc2d880) =
         *(undefined *)(uVar3 * 0x86 + uVar1 + -0x7fc2d880);
    (&DAT_803d27a0)[uVar2 * 0x86 + uVar1] = (&DAT_803d27a0)[uVar3 * 0x86 + uVar1];
    return;
  }
  if ((param_1 - 0x80 & 0xff) < 2) {
    uVar1 = param_1 & 0xfe;
    *(undefined *)(uVar2 * 0x86 + uVar1 + -0x7fc2d880) =
         *(undefined *)(uVar3 * 0x86 + uVar1 + -0x7fc2d880);
    (&DAT_803d2781)[uVar2 * 0x86 + uVar1] = (&DAT_803d2781)[uVar3 * 0x86 + uVar1];
    return;
  }
  if ((param_1 - 0x84 & 0xff) < 2) {
    uVar1 = param_1 & 0xfe;
    *(undefined *)(uVar2 * 0x86 + uVar1 + -0x7fc2d880) =
         *(undefined *)(uVar3 * 0x86 + uVar1 + -0x7fc2d880);
    (&DAT_803d2781)[uVar2 * 0x86 + uVar1] = (&DAT_803d2781)[uVar3 * 0x86 + uVar1];
    return;
  }
  *(undefined *)(uVar2 * 0x86 + uVar1 + -0x7fc2d880) =
       *(undefined *)(uVar3 * 0x86 + uVar1 + -0x7fc2d880);
  return;
}

