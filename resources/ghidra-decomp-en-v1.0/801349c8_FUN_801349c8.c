// Function: FUN_801349c8
// Entry: 801349c8
// Size: 500 bytes

void FUN_801349c8(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = (uint)DAT_803dd998;
  if (uVar3 < DAT_803dbc0a) {
    if (DAT_803dd9a8 < 1) {
      uVar2 = (uint)DAT_803dd996;
      if (uVar2 < 0x14) {
        uVar3 = (uVar2 * 0xff) / 0x14 & 0xff;
      }
      else if ((int)uVar2 < (int)(*(ushort *)(&DAT_8031ce92 + uVar3 * 4) - 0x14)) {
        uVar3 = 0xff;
      }
      else {
        if ((uVar3 == DAT_803dbc0a - 1) && (DAT_803dd9a4 == 0)) {
          FUN_8000a380(3,2,4000);
          DAT_803dd9a4 = 1;
        }
        iVar1 = ((uint)DAT_803dd996 - (uint)*(ushort *)(&DAT_8031ce92 + (uint)DAT_803dd998 * 4)) *
                0xff;
        iVar1 = iVar1 / 0x14 + (iVar1 >> 0x1f);
        uVar3 = 0xffU - (iVar1 - (iVar1 >> 0x1f)) & 0xff;
      }
      FUN_80019908(0xff,0xff,0xff,uVar3);
      FUN_80016810(*(undefined2 *)(&DAT_8031ce90 + (uint)DAT_803dd998 * 4),0,0);
      DAT_803dd994 = DAT_803dd994 + (ushort)DAT_803db411;
      DAT_803dd996 = DAT_803dd996 + DAT_803db411;
      if (*(ushort *)(&DAT_8031ce92 + (uint)DAT_803dd998 * 4) <= DAT_803dd996) {
        uVar3 = DAT_803dd998 + 1;
        DAT_803dd998 = (ushort)uVar3;
        DAT_803dd9a8 = 0x3c;
        if ((uVar3 & 0xffff) < (uint)DAT_803dbc0a) {
          DAT_803dd996 = 0;
        }
      }
    }
    else {
      DAT_803dd9a8 = DAT_803dd9a8 - (ushort)DAT_803db411;
      if (DAT_803dd9a8 < 0) {
        DAT_803dd9a8 = 0;
      }
    }
  }
  else {
    iVar1 = (**(code **)(*DAT_803dca50 + 0x10))();
    if (iVar1 == 0x57) {
      DAT_803dd993 = 0;
      FUN_80014948(4);
      FUN_80116f44(4);
    }
  }
  return;
}

