// Function: FUN_80204e28
// Entry: 80204e28
// Size: 316 bytes

void FUN_80204e28(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_800372f8(param_1,9);
  uVar2 = FUN_80020078(0xd5d);
  *(byte *)(iVar3 + 7) = (byte)((uVar2 & 0xff) << 7) | *(byte *)(iVar3 + 7) & 0x7f;
  uVar2 = FUN_80020078(0xd59);
  *(byte *)(iVar3 + 7) = (byte)((uVar2 & 0xff) << 6) & 0x40 | *(byte *)(iVar3 + 7) & 0xbf;
  uVar2 = FUN_80020078(0xd5a);
  *(byte *)(iVar3 + 7) = (byte)((uVar2 & 0xff) << 5) & 0x20 | *(byte *)(iVar3 + 7) & 0xdf;
  *(code **)(param_1 + 0xbc) = FUN_80204b24;
  *(undefined2 *)(iVar3 + 2) = 1;
  sVar1 = *(short *)(param_2 + 0x1a);
  if ((sVar1 != 0) && (sVar1 < 3)) {
    *(short *)(iVar3 + 2) = sVar1;
  }
  (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  FUN_80043604(0,0,1);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  if (*(char *)(param_1 + 0xac) == '\x15') {
    FUN_800201ac(0xdce,0);
  }
  uVar2 = FUN_80020078(0xdce);
  if (uVar2 != 0) {
    FUN_8000a538((int *)0x37,0);
    FUN_8000a538((int *)0xe4,0);
  }
  return;
}

