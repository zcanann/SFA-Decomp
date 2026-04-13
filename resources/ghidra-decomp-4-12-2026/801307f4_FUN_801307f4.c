// Function: FUN_801307f4
// Entry: 801307f4
// Size: 268 bytes

void FUN_801307f4(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined2 *puVar6;
  
  iVar4 = 0x1e0;
  iVar3 = 0;
  puVar6 = &DAT_803aa0b8;
  for (iVar5 = 0; iVar5 < DAT_803de591; iVar5 = iVar5 + 1) {
    if (((puVar6[0xb] & 4) == 0) || (*(char *)((int)puVar6 + 0x1f) == -1)) {
      iVar2 = *(int *)(puVar6 + 8);
    }
    else {
      iVar2 = (&DAT_8031ce04)[*(char *)((int)puVar6 + 0x1f) * 2];
    }
    if (iVar2 == 0) {
      iVar2 = FUN_80019c30();
      uVar1 = *(ushort *)(&DAT_802c8e0a + (uint)(byte)(&DAT_802c7b54)[iVar2 * 8] * 0x10) + 2;
      iVar2 = (short)puVar6[3] + -2;
    }
    else {
      uVar1 = (uint)*(ushort *)(iVar2 + 0xc);
      iVar2 = (int)(short)puVar6[6];
    }
    if (iVar2 < iVar4) {
      iVar4 = iVar2;
    }
    if (iVar3 < (int)(iVar2 + uVar1)) {
      iVar3 = iVar2 + uVar1;
    }
    puVar6 = puVar6 + 0x1e;
  }
  return;
}

