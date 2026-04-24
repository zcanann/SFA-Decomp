// Function: FUN_80130618
// Entry: 80130618
// Size: 444 bytes

void FUN_80130618(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined2 *puVar6;
  
  iVar1 = (int)DAT_803de592;
  (&DAT_803aa0f0)[iVar1 * 0x3c] = 4;
  if ((((&DAT_803aa0ce)[iVar1 * 0x1e] & 4) == 0) || ((char)(&DAT_803aa0d7)[iVar1 * 0x3c] == -1)) {
    iVar4 = (&DAT_803aa0c8)[iVar1 * 0xf];
  }
  else {
    iVar4 = (&DAT_8031ce04)[(char)(&DAT_803aa0d7)[iVar1 * 0x3c] * 2];
  }
  if (iVar4 == 0) {
    iVar4 = FUN_80019c30();
    uVar2 = *(ushort *)(&DAT_802c8e0a + (uint)(byte)(&DAT_802c7b54)[iVar4 * 8] * 0x10) + 2;
    iVar1 = (short)(&DAT_803aa0be)[iVar1 * 0x1e] + -2;
  }
  else {
    uVar2 = (uint)*(ushort *)(iVar4 + 0xc);
    iVar1 = (int)(short)(&DAT_803aa0c4)[iVar1 * 0x1e];
  }
  puVar6 = &DAT_803aa0b8;
  for (iVar4 = 0; iVar4 < DAT_803de591; iVar4 = iVar4 + 1) {
    if (iVar4 != DAT_803de592) {
      if (((puVar6[0xb] & 4) == 0) || (*(char *)((int)puVar6 + 0x1f) == -1)) {
        iVar5 = *(int *)(puVar6 + 8);
      }
      else {
        iVar5 = (&DAT_8031ce04)[*(char *)((int)puVar6 + 0x1f) * 2];
      }
      if (iVar5 == 0) {
        iVar5 = FUN_80019c30();
        uVar3 = *(ushort *)(&DAT_802c8e0a + (uint)(byte)(&DAT_802c7b54)[iVar5 * 8] * 0x10) + 2;
        iVar5 = (short)puVar6[3] + -2;
      }
      else {
        uVar3 = (uint)*(ushort *)(iVar5 + 0xc);
        iVar5 = (int)(short)puVar6[6];
      }
      if ((iVar5 < (int)(iVar1 + uVar2)) && (iVar1 < (int)(iVar5 + uVar3))) {
        *(undefined *)(puVar6 + 0x1c) = 4;
      }
    }
    puVar6 = puVar6 + 0x1e;
  }
  return;
}

