// Function: FUN_80221648
// Entry: 80221648
// Size: 376 bytes

void FUN_80221648(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80020078(0xe30);
  *(byte *)(iVar2 + 8) = (byte)((uVar1 & 0xff) << 5) & 0x20 | *(byte *)(iVar2 + 8) & 0xdf;
  uVar1 = FUN_80020078(0xe31);
  *(byte *)(iVar2 + 8) = (byte)((uVar1 & 0xff) << 4) & 0x10 | *(byte *)(iVar2 + 8) & 0xef;
  uVar1 = FUN_80020078(0xe32);
  *(byte *)(iVar2 + 8) = (byte)((uVar1 & 0xff) << 3) & 8 | *(byte *)(iVar2 + 8) & 0xf7;
  uVar1 = FUN_80020078(0xe33);
  *(byte *)(iVar2 + 8) = (byte)((uVar1 & 0xff) << 2) & 4 | *(byte *)(iVar2 + 8) & 0xfb;
  uVar1 = FUN_80020078(0xe9c);
  *(byte *)(iVar2 + 8) = (byte)((uVar1 & 0xff) << 1) & 2 | *(byte *)(iVar2 + 8) & 0xfd;
  uVar1 = FUN_80020078(0xe38);
  *(byte *)(iVar2 + 8) = (byte)uVar1 & 1 | *(byte *)(iVar2 + 8) & 0xfe;
  uVar1 = FUN_80020078(0xe3c);
  *(byte *)(iVar2 + 9) = (byte)((uVar1 & 0xff) << 7) | *(byte *)(iVar2 + 9) & 0x7f;
  uVar1 = FUN_80020078(0xe3d);
  *(byte *)(iVar2 + 9) = (byte)((uVar1 & 0xff) << 6) & 0x40 | *(byte *)(iVar2 + 9) & 0xbf;
  uVar1 = FUN_80020078(0xe3e);
  *(byte *)(iVar2 + 9) = (byte)((uVar1 & 0xff) << 5) & 0x20 | *(byte *)(iVar2 + 9) & 0xdf;
  uVar1 = FUN_80020078(0xe39);
  *(byte *)(iVar2 + 9) = (byte)((uVar1 & 0xff) << 4) & 0x10 | *(byte *)(iVar2 + 9) & 0xef;
  uVar1 = FUN_80020078(0x9e0);
  *(byte *)(iVar2 + 9) = (byte)((uVar1 & 0xff) << 3) & 8 | *(byte *)(iVar2 + 9) & 0xf7;
  uVar1 = FUN_80020078(0x9e1);
  *(byte *)(iVar2 + 9) = (byte)((uVar1 & 0xff) << 2) & 4 | *(byte *)(iVar2 + 9) & 0xfb;
  uVar1 = FUN_80020078(0x9e2);
  *(byte *)(iVar2 + 9) = (byte)((uVar1 & 0xff) << 1) & 2 | *(byte *)(iVar2 + 9) & 0xfd;
  uVar1 = FUN_80020078(0x9e7);
  *(byte *)(iVar2 + 9) = (byte)uVar1 & 1 | *(byte *)(iVar2 + 9) & 0xfe;
  return;
}

