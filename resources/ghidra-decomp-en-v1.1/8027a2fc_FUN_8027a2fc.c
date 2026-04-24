// Function: FUN_8027a2fc
// Entry: 8027a2fc
// Size: 228 bytes

void FUN_8027a2fc(int param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  
  FUN_802791fc(param_1,2);
  FUN_80279c50(param_1);
  *(undefined4 *)(param_1 + 0x34) = 0;
  *(undefined *)(param_1 + 0x10c) = 0;
  bVar1 = (byte)*(uint *)(param_1 + 0xf4);
  uVar2 = *(uint *)(param_1 + 0xf4) & 0xff;
  iVar3 = uVar2 * 4;
  if ((&DAT_803cbdf2)[uVar2 * 2] == 0) {
    (&DAT_803cbdf2)[uVar2 * 2] = 1;
    if (DAT_803def81 == 0xff) {
      (&DAT_803cbdf1)[iVar3] = 0xff;
      (&DAT_803cbdf0)[iVar3] = 0xff;
      DAT_803def81 = bVar1;
    }
    else {
      (&DAT_803cbdf1)[iVar3] = 0xff;
      (&DAT_803cbdf0)[iVar3] = DAT_803def80;
      (&DAT_803cbdf1)[(uint)DAT_803def80 * 4] = bVar1;
    }
    DAT_803def80 = bVar1;
    if (*(char *)(param_1 + 0x11d) == '\0') {
      DAT_803def7e = DAT_803def7e + -1;
    }
    else {
      DAT_803def7f = DAT_803def7f + -1;
    }
  }
  *(undefined4 *)(param_1 + 0xf4) = 0xffffffff;
  return;
}

