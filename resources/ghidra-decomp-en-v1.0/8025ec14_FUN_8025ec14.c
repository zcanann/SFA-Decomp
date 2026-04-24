// Function: FUN_8025ec14
// Entry: 8025ec14
// Size: 224 bytes

int FUN_8025ec14(int param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = param_1 * 0x110;
  (&DAT_803af274)[iVar2] = 0xf1;
  (&DAT_803af275)[iVar2] = (byte)(param_2 >> 0x11) & 0x7f;
  (&DAT_803af276)[iVar2] = (char)(param_2 >> 9);
  *(undefined4 *)(&DAT_803af280 + iVar2) = 3;
  *(undefined4 *)(&DAT_803af284 + iVar2) = 0xffffffff;
  *(undefined4 *)(&DAT_803af288 + iVar2) = 3;
  iVar1 = FUN_8025e810(param_1,0);
  if (iVar1 == -1) {
    iVar1 = 0;
  }
  else if (-1 < iVar1) {
    iVar1 = FUN_802534d8(param_1,&DAT_803af274 + iVar2,*(undefined4 *)(&DAT_803af280 + iVar2),1);
    if (iVar1 == 0) {
      *(undefined4 *)(&DAT_803af2ac + iVar2) = 0;
      iVar1 = -3;
    }
    else {
      iVar1 = 0;
    }
    FUN_80253efc(param_1);
    FUN_802545c4(param_1);
  }
  return iVar1;
}

