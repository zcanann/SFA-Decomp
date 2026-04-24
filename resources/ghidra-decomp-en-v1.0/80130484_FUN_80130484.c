// Function: FUN_80130484
// Entry: 80130484
// Size: 244 bytes

void FUN_80130484(void)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  undefined2 *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  FUN_802860dc();
  iVar6 = 0x1e0;
  iVar5 = 0;
  puVar4 = &DAT_803a9458;
  for (iVar7 = 0; iVar7 < DAT_803dd911; iVar7 = iVar7 + 1) {
    if (((puVar4[0xb] & 4) == 0) || (*(char *)((int)puVar4 + 0x1f) == -1)) {
      iVar3 = *(int *)(puVar4 + 8);
    }
    else {
      iVar3 = (&DAT_8031c1b4)[*(char *)((int)puVar4 + 0x1f) * 2];
    }
    if (iVar3 == 0) {
      iVar3 = FUN_80019bf8();
      uVar1 = DAT_802c86ca;
      if (iVar3 == 4) {
        uVar1 = DAT_802c868a;
      }
      uVar2 = uVar1 + 2;
      iVar3 = (short)puVar4[3] + -2;
    }
    else {
      uVar2 = (uint)*(ushort *)(iVar3 + 0xc);
      iVar3 = (int)(short)puVar4[6];
    }
    if (iVar3 < iVar6) {
      iVar6 = iVar3;
    }
    if (iVar5 < (int)(iVar3 + uVar2)) {
      iVar5 = iVar3 + uVar2;
    }
    puVar4 = puVar4 + 0x1e;
  }
  FUN_80286128();
  return;
}

