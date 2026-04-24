// Function: FUN_802c0b84
// Entry: 802c0b84
// Size: 120 bytes

undefined4 FUN_802c0b84(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar2 + 0xbb4) == '\0') {
    uVar1 = 2;
  }
  else {
    FUN_80035f20();
    FUN_80035ea4(param_1);
    *(byte *)(iVar2 + 0xbc0) =
         (byte)(((uint)(-(int)*(short *)(iVar2 + 0xbb0) & ~(int)*(short *)(iVar2 + 0xbb0)) >> 0x1f)
               << 4) | *(byte *)(iVar2 + 0xbc0) & 0xef;
    uVar1 = 3;
  }
  return uVar1;
}

