// Function: FUN_80279c50
// Entry: 80279c50
// Size: 224 bytes

void FUN_80279c50(int param_1)

{
  uint uVar1;
  int iVar2;
  ushort *puVar3;
  byte *pbVar4;
  
  uVar1 = *(uint *)(param_1 + 0xf4) & 0xff;
  iVar2 = uVar1 * 4;
  pbVar4 = &DAT_803cb7f0 + iVar2;
  if ((&DAT_803cb7f2)[uVar1 * 2] != 1) {
    return;
  }
  if (*pbVar4 == 0xff) {
    (&DAT_803cb8f0)[*(byte *)(param_1 + 0x10c)] = (&DAT_803cb7f1)[iVar2];
  }
  else {
    (&DAT_803cb7f1)[(uint)*pbVar4 * 4] = (&DAT_803cb7f1)[iVar2];
  }
  if ((byte)(&DAT_803cb7f1)[iVar2] == 0xff) {
    if (*pbVar4 == 0xff) {
      iVar2 = (uint)*(byte *)(param_1 + 0x10c) * 4;
      puVar3 = (ushort *)(&DAT_803cb9f0 + iVar2);
      if (*(ushort *)(&DAT_803cb9f2 + iVar2) == 0xffff) {
        DAT_803def7c = *puVar3;
      }
      else {
        *(ushort *)(&DAT_803cb9f0 + (uint)*(ushort *)(&DAT_803cb9f2 + iVar2) * 4) = *puVar3;
      }
      if (*puVar3 != 0xffff) {
        *(undefined2 *)(&DAT_803cb9f2 + (uint)*puVar3 * 4) = *(undefined2 *)(&DAT_803cb9f2 + iVar2);
      }
    }
  }
  else {
    (&DAT_803cb7f0)[(uint)(byte)(&DAT_803cb7f1)[iVar2] * 4] = *pbVar4;
  }
  (&DAT_803cb7f2)[uVar1 * 2] = 0;
  return;
}

