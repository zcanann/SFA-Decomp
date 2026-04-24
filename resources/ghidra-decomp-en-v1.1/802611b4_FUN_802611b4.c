// Function: FUN_802611b4
// Entry: 802611b4
// Size: 196 bytes

int FUN_802611b4(int param_1,undefined4 param_2)

{
  int iVar1;
  ushort *puVar2;
  
  iVar1 = param_1 * 0x110;
  if ((&DAT_803afe40)[param_1 * 0x44] == 0) {
    iVar1 = -3;
  }
  else {
    puVar2 = *(ushort **)(&DAT_803afec4 + iVar1);
    puVar2[0xffd] = puVar2[0xffd] + 1;
    FUN_80261278(puVar2,0x1ffc,(short *)(puVar2 + 0xffe),(short *)(puVar2 + 0xfff));
    FUN_80242114((uint)puVar2,0x2000);
    *(undefined4 *)(&DAT_803aff18 + iVar1) = param_2;
    iVar1 = FUN_8025f378(param_1,*(int *)(&DAT_803afe4c + iVar1) *
                                 ((uint)((int)puVar2 - (&DAT_803afec0)[param_1 * 0x44]) >> 0xd),
                         -0x7fd9ef14);
  }
  return iVar1;
}

