// Function: FUN_80281ecc
// Entry: 80281ecc
// Size: 284 bytes

void FUN_80281ecc(uint param_1,int param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar1 = param_1 & 0xff;
  uVar2 = *(uint *)(param_2 + 0xf4) & 0xff;
  uVar3 = *(uint *)(param_3 + 0xf4) & 0xff;
  if (uVar1 < 0x40) {
    param_1 = param_1 & 0x1f;
    *(undefined *)(uVar2 * 0x86 + param_1 + -0x7fc2e4e0) =
         *(undefined *)(uVar3 * 0x86 + param_1 + -0x7fc2e4e0);
    (&DAT_803d1b40)[uVar2 * 0x86 + param_1] = (&DAT_803d1b40)[uVar3 * 0x86 + param_1];
    return;
  }
  if ((param_1 - 0x80 & 0xff) < 2) {
    param_1 = param_1 & 0xfe;
    *(undefined *)(uVar2 * 0x86 + param_1 + -0x7fc2e4e0) =
         *(undefined *)(uVar3 * 0x86 + param_1 + -0x7fc2e4e0);
    (&DAT_803d1b21)[uVar2 * 0x86 + param_1] = (&DAT_803d1b21)[uVar3 * 0x86 + param_1];
    return;
  }
  if ((param_1 - 0x84 & 0xff) < 2) {
    param_1 = param_1 & 0xfe;
    *(undefined *)(uVar2 * 0x86 + param_1 + -0x7fc2e4e0) =
         *(undefined *)(uVar3 * 0x86 + param_1 + -0x7fc2e4e0);
    (&DAT_803d1b21)[uVar2 * 0x86 + param_1] = (&DAT_803d1b21)[uVar3 * 0x86 + param_1];
    return;
  }
  *(undefined *)(uVar2 * 0x86 + uVar1 + -0x7fc2e4e0) =
       *(undefined *)(uVar3 * 0x86 + uVar1 + -0x7fc2e4e0);
  return;
}

