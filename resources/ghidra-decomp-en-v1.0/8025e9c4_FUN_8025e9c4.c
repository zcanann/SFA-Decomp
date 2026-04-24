// Function: FUN_8025e9c4
// Entry: 8025e9c4
// Size: 308 bytes

int FUN_8025e9c4(int param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = param_1 * 0x110;
  (&DAT_803af274)[iVar2] = 0x52;
  (&DAT_803af275)[iVar2] = (byte)(*(uint *)(&DAT_803af290 + iVar2) >> 0x11) & 0x7f;
  (&DAT_803af276)[iVar2] = (char)(*(uint *)(&DAT_803af290 + iVar2) >> 9);
  (&DAT_803af277)[iVar2] = (byte)(*(uint *)(&DAT_803af290 + iVar2) >> 7) & 3;
  (&DAT_803af278)[iVar2] = (byte)*(undefined4 *)(&DAT_803af290 + iVar2) & 0x7f;
  *(undefined4 *)(&DAT_803af280 + iVar2) = 5;
  *(undefined4 *)(&DAT_803af284 + iVar2) = 0;
  *(undefined4 *)(&DAT_803af288 + iVar2) = 0;
  iVar1 = FUN_8025e810(param_1,param_2,0);
  if (iVar1 == -1) {
    iVar1 = 0;
  }
  else if (-1 < iVar1) {
    iVar1 = FUN_802534d8(param_1,&DAT_803af274 + iVar2,*(undefined4 *)(&DAT_803af280 + iVar2),1);
    if (((iVar1 == 0) ||
        (iVar1 = FUN_802534d8(param_1,(&DAT_803af260)[param_1 * 0x44] + 0x200,
                              *(undefined4 *)(&DAT_803af1f4 + iVar2),1), iVar1 == 0)) ||
       (iVar1 = FUN_80253578(param_1,*(undefined4 *)(&DAT_803af294 + iVar2),0x200,
                             *(undefined4 *)(&DAT_803af284 + iVar2),&LAB_8025e0a8), iVar1 == 0)) {
      *(undefined4 *)(&DAT_803af2a8 + iVar2) = 0;
      FUN_80253efc(param_1);
      FUN_802545c4(param_1);
      iVar1 = -3;
    }
    else {
      iVar1 = 0;
    }
  }
  return iVar1;
}

