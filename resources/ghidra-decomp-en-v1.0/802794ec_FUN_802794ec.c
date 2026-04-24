// Function: FUN_802794ec
// Entry: 802794ec
// Size: 224 bytes

void FUN_802794ec(int param_1)

{
  uint uVar1;
  int iVar2;
  ushort *puVar3;
  byte *pbVar4;
  
  uVar1 = *(uint *)(param_1 + 0xf4) & 0xff;
  iVar2 = uVar1 * 4;
  pbVar4 = &DAT_803cab90 + iVar2;
  if ((&DAT_803cab92)[uVar1 * 2] != 1) {
    return;
  }
  if (*pbVar4 == 0xff) {
    (&DAT_803cac90)[*(byte *)(param_1 + 0x10c)] = (&DAT_803cab91)[iVar2];
  }
  else {
    (&DAT_803cab91)[(uint)*pbVar4 * 4] = (&DAT_803cab91)[iVar2];
  }
  if ((byte)(&DAT_803cab91)[iVar2] == 0xff) {
    if (*pbVar4 == 0xff) {
      iVar2 = (uint)*(byte *)(param_1 + 0x10c) * 4;
      puVar3 = (ushort *)(&DAT_803cad90 + iVar2);
      if (*(ushort *)(&DAT_803cad92 + iVar2) == 0xffff) {
        DAT_803de2fc = *puVar3;
      }
      else {
        *(ushort *)(&DAT_803cad90 + (uint)*(ushort *)(&DAT_803cad92 + iVar2) * 4) = *puVar3;
      }
      if (*puVar3 != 0xffff) {
        *(undefined2 *)(&DAT_803cad92 + (uint)*puVar3 * 4) = *(undefined2 *)(&DAT_803cad92 + iVar2);
      }
    }
  }
  else {
    (&DAT_803cab90)[(uint)(byte)(&DAT_803cab91)[iVar2] * 4] = *pbVar4;
  }
  (&DAT_803cab92)[uVar1 * 2] = 0;
  return;
}

