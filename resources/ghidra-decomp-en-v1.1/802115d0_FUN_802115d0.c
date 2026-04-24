// Function: FUN_802115d0
// Entry: 802115d0
// Size: 220 bytes

void FUN_802115d0(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_800803dc((float *)(iVar2 + 0xc));
  if (uVar1 == 0) {
    if (*(byte *)(param_1 + 0x36) < 0xff) {
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      FUN_80080404((float *)(iVar2 + 0xc),0x708);
    }
    else {
      iVar2 = (int)*(short *)(iVar3 + 0x1a);
      iVar2 = iVar2 / 10 + (iVar2 >> 0x1f);
      FUN_80035eec(param_1,0x1d,(char)iVar2 - (char)(iVar2 >> 0x1f),0);
    }
  }
  else {
    iVar2 = FUN_80080434((float *)(iVar2 + 0xc));
    if (iVar2 != 0) {
      FUN_80036018(param_1);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
      *(undefined *)(param_1 + 0x36) = 0xff;
    }
  }
  return;
}

