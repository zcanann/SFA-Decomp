// Function: FUN_8022705c
// Entry: 8022705c
// Size: 612 bytes

void FUN_8022705c(int param_1)

{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_80225bd8;
  FUN_800200e8(0x810,0);
  FUN_80003494(&DAT_803ad2d8,&DAT_8032b008,0x40);
  FUN_800200e8(0x811,0);
  FUN_80003494(&DAT_803ad298,&DAT_8032b088,0x40);
  iVar2 = FUN_8001ffb4(0x7fa);
  if (iVar2 != 0) {
    *(ushort *)(iVar4 + 0x1a) = *(ushort *)(iVar4 + 0x1a) | 8;
  }
  iVar2 = FUN_8001ffb4(0x7f9);
  if (iVar2 != 0) {
    *(ushort *)(iVar4 + 0x1a) = *(ushort *)(iVar4 + 0x1a) | 4;
  }
  iVar2 = FUN_8001ffb4(0x813);
  if (iVar2 != 0) {
    *(ushort *)(iVar4 + 0x1a) = *(ushort *)(iVar4 + 0x1a) | 0x20;
  }
  iVar2 = FUN_8001ffb4(0x812);
  if (iVar2 != 0) {
    *(ushort *)(iVar4 + 0x1a) = *(ushort *)(iVar4 + 0x1a) | 0x10;
  }
  iVar2 = FUN_8001ffb4(0x2a5);
  if (iVar2 != 0) {
    *(ushort *)(iVar4 + 0x1a) = *(ushort *)(iVar4 + 0x1a) | 0x40;
  }
  iVar2 = FUN_8001ffb4(0x205);
  if (iVar2 != 0) {
    *(ushort *)(iVar4 + 0x1a) = *(ushort *)(iVar4 + 0x1a) | 0x80;
  }
  iVar2 = FUN_8001ffb4(0xbcf);
  if (iVar2 != 0) {
    *(ushort *)(iVar4 + 0x1a) = *(ushort *)(iVar4 + 0x1a) | 0x100;
  }
  iVar2 = FUN_8001ffb4(0xcac);
  if (iVar2 != 0) {
    *(ushort *)(iVar4 + 0x1a) = *(ushort *)(iVar4 + 0x1a) | 0x200;
  }
  uVar1 = *(ushort *)(iVar4 + 0x1a);
  if ((uVar1 & 0x200) == 0) {
    if (((uVar1 & 4) != 0) && ((uVar1 & 8) != 0)) {
      *(undefined *)(iVar4 + 0xc) = 3;
    }
  }
  else {
    *(undefined *)(iVar4 + 0xc) = 7;
  }
  FUN_80037200(param_1,9);
  FUN_800200e8(0x226,1);
  FUN_800200e8(0x2a6,1);
  FUN_800200e8(0x206,1);
  FUN_800200e8(0x25f,1);
  (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  uVar3 = FUN_8001ffb4(0xc58);
  *(byte *)(iVar4 + 0x14) = (byte)((uVar3 & 0xff) << 6) & 0x40 | *(byte *)(iVar4 + 0x14) & 0xbf;
  uVar3 = FUN_8001ffb4(0xc59);
  *(byte *)(iVar4 + 0x14) = (byte)((uVar3 & 0xff) << 5) & 0x20 | *(byte *)(iVar4 + 0x14) & 0xdf;
  uVar3 = FUN_8001ffb4(0xc5a);
  *(byte *)(iVar4 + 0x14) = (byte)((uVar3 & 0xff) << 3) & 0x18 | *(byte *)(iVar4 + 0x14) & 0xe7;
  return;
}

