// Function: FUN_802047f0
// Entry: 802047f0
// Size: 316 bytes

void FUN_802047f0(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_80037200(param_1,9);
  uVar2 = FUN_8001ffb4(0xd5d);
  *(byte *)(iVar3 + 7) = (byte)((uVar2 & 0xff) << 7) | *(byte *)(iVar3 + 7) & 0x7f;
  uVar2 = FUN_8001ffb4(0xd59);
  *(byte *)(iVar3 + 7) = (byte)((uVar2 & 0xff) << 6) & 0x40 | *(byte *)(iVar3 + 7) & 0xbf;
  uVar2 = FUN_8001ffb4(0xd5a);
  *(byte *)(iVar3 + 7) = (byte)((uVar2 & 0xff) << 5) & 0x20 | *(byte *)(iVar3 + 7) & 0xdf;
  *(code **)(param_1 + 0xbc) = FUN_802044ec;
  *(undefined2 *)(iVar3 + 2) = 1;
  sVar1 = *(short *)(param_2 + 0x1a);
  if ((sVar1 != 0) && (sVar1 < 3)) {
    *(short *)(iVar3 + 2) = sVar1;
  }
  (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  FUN_8004350c(0,0,1);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x4000;
  if (*(char *)(param_1 + 0xac) == '\x15') {
    FUN_800200e8(0xdce,0);
  }
  iVar3 = FUN_8001ffb4(0xdce);
  if (iVar3 != 0) {
    FUN_8000a518(0x37,0);
    FUN_8000a518(0xe4,0);
  }
  return;
}

