// Function: FUN_80279b98
// Entry: 80279b98
// Size: 228 bytes

void FUN_80279b98(int param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  
  FUN_80278a98(param_1,2);
  FUN_802794ec(param_1);
  *(undefined4 *)(param_1 + 0x34) = 0;
  *(undefined *)(param_1 + 0x10c) = 0;
  bVar1 = (byte)*(uint *)(param_1 + 0xf4);
  uVar2 = *(uint *)(param_1 + 0xf4) & 0xff;
  iVar3 = uVar2 * 4;
  if ((&DAT_803cb192)[uVar2 * 2] == 0) {
    (&DAT_803cb192)[uVar2 * 2] = 1;
    if (DAT_803de301 == 0xff) {
      (&DAT_803cb191)[iVar3] = 0xff;
      (&DAT_803cb190)[iVar3] = 0xff;
      DAT_803de301 = bVar1;
    }
    else {
      (&DAT_803cb191)[iVar3] = 0xff;
      (&DAT_803cb190)[iVar3] = DAT_803de300;
      (&DAT_803cb191)[(uint)DAT_803de300 * 4] = bVar1;
    }
    DAT_803de300 = bVar1;
    if (*(char *)(param_1 + 0x11d) == '\0') {
      DAT_803de2fe = DAT_803de2fe + -1;
    }
    else {
      DAT_803de2ff = DAT_803de2ff + -1;
    }
  }
  *(undefined4 *)(param_1 + 0xf4) = 0xffffffff;
  return;
}

