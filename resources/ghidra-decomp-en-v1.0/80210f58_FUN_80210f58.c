// Function: FUN_80210f58
// Entry: 80210f58
// Size: 220 bytes

void FUN_80210f58(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_80080150(iVar2 + 0xc);
  if (iVar1 == 0) {
    if (*(byte *)(param_1 + 0x36) < 0xff) {
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      FUN_80080178(iVar2 + 0xc,0x708);
    }
    else {
      iVar1 = (int)*(short *)(iVar3 + 0x1a);
      iVar1 = iVar1 / 10 + (iVar1 >> 0x1f);
      FUN_80035df4(param_1,0x1d,iVar1 - (iVar1 >> 0x1f),0);
    }
  }
  else {
    iVar1 = FUN_800801a8(iVar2 + 0xc);
    if (iVar1 != 0) {
      FUN_80035f20(param_1);
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
      *(undefined *)(param_1 + 0x36) = 0xff;
    }
  }
  return;
}

