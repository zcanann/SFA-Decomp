// Function: FUN_801302c0
// Entry: 801302c0
// Size: 420 bytes

void FUN_801302c0(void)

{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  undefined2 *puVar7;
  
  FUN_802860dc();
  iVar2 = (int)DAT_803dd912;
  (&DAT_803a9490)[iVar2 * 0x3c] = 4;
  if ((((&DAT_803a946e)[iVar2 * 0x1e] & 4) == 0) || ((char)(&DAT_803a9477)[iVar2 * 0x3c] == -1)) {
    iVar5 = (&DAT_803a9468)[iVar2 * 0xf];
  }
  else {
    iVar5 = (&DAT_8031c1b4)[(char)(&DAT_803a9477)[iVar2 * 0x3c] * 2];
  }
  if (iVar5 == 0) {
    iVar5 = FUN_80019bf8();
    uVar1 = DAT_802c86ca;
    if (iVar5 == 4) {
      uVar1 = DAT_802c868a;
    }
    uVar3 = uVar1 + 2;
    iVar2 = (short)(&DAT_803a945e)[iVar2 * 0x1e] + -2;
  }
  else {
    uVar3 = (uint)*(ushort *)(iVar5 + 0xc);
    iVar2 = (int)(short)(&DAT_803a9464)[iVar2 * 0x1e];
  }
  puVar7 = &DAT_803a9458;
  for (iVar5 = 0; iVar5 < DAT_803dd911; iVar5 = iVar5 + 1) {
    if (iVar5 != DAT_803dd912) {
      if (((puVar7[0xb] & 4) == 0) || (*(char *)((int)puVar7 + 0x1f) == -1)) {
        iVar6 = *(int *)(puVar7 + 8);
      }
      else {
        iVar6 = (&DAT_8031c1b4)[*(char *)((int)puVar7 + 0x1f) * 2];
      }
      if (iVar6 == 0) {
        iVar6 = FUN_80019bf8();
        uVar1 = DAT_802c86ca;
        if (iVar6 == 4) {
          uVar1 = DAT_802c868a;
        }
        uVar4 = uVar1 + 2;
        iVar6 = (short)puVar7[3] + -2;
      }
      else {
        uVar4 = (uint)*(ushort *)(iVar6 + 0xc);
        iVar6 = (int)(short)puVar7[6];
      }
      if ((iVar6 < (int)(iVar2 + uVar3)) && (iVar2 < (int)(iVar6 + uVar4))) {
        *(undefined *)(puVar7 + 0x1c) = 4;
      }
    }
    puVar7 = puVar7 + 0x1e;
  }
  FUN_80286128();
  return;
}

