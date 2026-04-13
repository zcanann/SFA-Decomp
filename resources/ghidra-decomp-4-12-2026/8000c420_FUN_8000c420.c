// Function: FUN_8000c420
// Entry: 8000c420
// Size: 184 bytes

ushort * FUN_8000c420(uint param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  ushort *puVar4;
  ushort *puVar5;
  ushort *puVar6;
  
  uVar3 = param_1 & 0xffff;
  iVar1 = (param_1 & 0xf) * 4;
  puVar5 = DAT_803dd4b0;
  puVar4 = DAT_803dd4b0 + DAT_803dd4b4 * 0x10;
  if (*(ushort *)(&DAT_802c64f8 + iVar1) == uVar3) {
    return DAT_803dd4b0 + (uint)*(ushort *)(&DAT_802c64fa + iVar1) * 0x10;
  }
  while( true ) {
    do {
      puVar6 = puVar4;
      if (puVar6 <= puVar5) {
        return (ushort *)0x0;
      }
      uVar2 = (int)puVar6 - (int)puVar5;
      puVar4 = puVar5 + ((int)(((int)uVar2 >> 5) + (uint)((int)uVar2 < 0 && (uVar2 & 0x1f) != 0)) /
                        2) * 0x10;
    } while (uVar3 < *puVar4);
    if (uVar3 <= *puVar4) break;
    puVar5 = puVar4 + 0x10;
    puVar4 = puVar6;
  }
  *(ushort *)(&DAT_802c64f8 + iVar1) = (ushort)param_1;
  uVar3 = (int)puVar4 - (int)DAT_803dd4b0;
  *(ushort *)(&DAT_802c64fa + iVar1) =
       (short)((int)uVar3 >> 5) + (ushort)((int)uVar3 < 0 && (uVar3 & 0x1f) != 0);
  return puVar4;
}

