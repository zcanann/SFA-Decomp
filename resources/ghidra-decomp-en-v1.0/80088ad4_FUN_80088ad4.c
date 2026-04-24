// Function: FUN_80088ad4
// Entry: 80088ad4
// Size: 312 bytes

void FUN_80088ad4(byte param_1)

{
  short sVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  iVar3 = FUN_8002b9ec();
  if ((((DAT_803dd134 != 0) && (iVar3 != 0)) && ((DAT_803dd140 & 8) != 0)) &&
     (iVar4 = FUN_8001ffb4(0x3b0), iVar4 == 0)) {
    cVar2 = param_1 - 1;
    if (cVar2 < '\0') {
      cVar2 = '\x1b';
    }
    sVar1 = *(short *)(DAT_803dd134 + (uint)param_1 * 2);
    if ((sVar1 < 1) || (*(short *)(DAT_803dd134 + cVar2 * 2) != sVar1)) {
      FUN_80008cbc(iVar3,iVar3,0x136,0);
      FUN_80008cbc(iVar3,iVar3,0x137,0);
      FUN_80008cbc(iVar3,iVar3,0x143,0);
    }
    uVar5 = (uint)*(short *)(DAT_803dd134 + (uint)param_1 * 2);
    if (0 < (int)uVar5) {
      if ((DAT_803dd140 & 0x20) == 0) {
        FUN_80008cbc(iVar3,iVar3,uVar5 & 0xffff,0);
      }
      else {
        FUN_80008b74(iVar3,iVar3,uVar5 & 0xffff,0);
      }
    }
  }
  return;
}

