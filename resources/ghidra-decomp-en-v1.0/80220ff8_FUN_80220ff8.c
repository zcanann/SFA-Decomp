// Function: FUN_80220ff8
// Entry: 80220ff8
// Size: 376 bytes

void FUN_80220ff8(int param_1)

{
  uint uVar1;
  byte bVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_8001ffb4(0xe30);
  *(byte *)(iVar3 + 8) = (byte)((uVar1 & 0xff) << 5) & 0x20 | *(byte *)(iVar3 + 8) & 0xdf;
  uVar1 = FUN_8001ffb4(0xe31);
  *(byte *)(iVar3 + 8) = (byte)((uVar1 & 0xff) << 4) & 0x10 | *(byte *)(iVar3 + 8) & 0xef;
  uVar1 = FUN_8001ffb4(0xe32);
  *(byte *)(iVar3 + 8) = (byte)((uVar1 & 0xff) << 3) & 8 | *(byte *)(iVar3 + 8) & 0xf7;
  uVar1 = FUN_8001ffb4(0xe33);
  *(byte *)(iVar3 + 8) = (byte)((uVar1 & 0xff) << 2) & 4 | *(byte *)(iVar3 + 8) & 0xfb;
  uVar1 = FUN_8001ffb4(0xe9c);
  *(byte *)(iVar3 + 8) = (byte)((uVar1 & 0xff) << 1) & 2 | *(byte *)(iVar3 + 8) & 0xfd;
  bVar2 = FUN_8001ffb4(0xe38);
  *(byte *)(iVar3 + 8) = bVar2 & 1 | *(byte *)(iVar3 + 8) & 0xfe;
  uVar1 = FUN_8001ffb4(0xe3c);
  *(byte *)(iVar3 + 9) = (byte)((uVar1 & 0xff) << 7) | *(byte *)(iVar3 + 9) & 0x7f;
  uVar1 = FUN_8001ffb4(0xe3d);
  *(byte *)(iVar3 + 9) = (byte)((uVar1 & 0xff) << 6) & 0x40 | *(byte *)(iVar3 + 9) & 0xbf;
  uVar1 = FUN_8001ffb4(0xe3e);
  *(byte *)(iVar3 + 9) = (byte)((uVar1 & 0xff) << 5) & 0x20 | *(byte *)(iVar3 + 9) & 0xdf;
  uVar1 = FUN_8001ffb4(0xe39);
  *(byte *)(iVar3 + 9) = (byte)((uVar1 & 0xff) << 4) & 0x10 | *(byte *)(iVar3 + 9) & 0xef;
  uVar1 = FUN_8001ffb4(0x9e0);
  *(byte *)(iVar3 + 9) = (byte)((uVar1 & 0xff) << 3) & 8 | *(byte *)(iVar3 + 9) & 0xf7;
  uVar1 = FUN_8001ffb4(0x9e1);
  *(byte *)(iVar3 + 9) = (byte)((uVar1 & 0xff) << 2) & 4 | *(byte *)(iVar3 + 9) & 0xfb;
  uVar1 = FUN_8001ffb4(0x9e2);
  *(byte *)(iVar3 + 9) = (byte)((uVar1 & 0xff) << 1) & 2 | *(byte *)(iVar3 + 9) & 0xfd;
  bVar2 = FUN_8001ffb4(0x9e7);
  *(byte *)(iVar3 + 9) = bVar2 & 1 | *(byte *)(iVar3 + 9) & 0xfe;
  return;
}

