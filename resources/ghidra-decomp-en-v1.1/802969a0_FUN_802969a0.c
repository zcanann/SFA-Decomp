// Function: FUN_802969a0
// Entry: 802969a0
// Size: 116 bytes

undefined4 FUN_802969a0(int param_1)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  bVar1 = *(byte *)(iVar2 + 0x3f0);
  if (((((bVar1 >> 2 & 1) == 0) && ((bVar1 >> 3 & 1) == 0)) && ((bVar1 >> 5 & 1) == 0)) &&
     (((bVar1 >> 4 & 1) == 0 && ((*(byte *)(iVar2 + 0x3f3) >> 3 & 1) == 0)))) {
    if ((*(short *)(iVar2 + 0x274) != 1) && (*(short *)(iVar2 + 0x274) != 2)) {
      return 0;
    }
    return 1;
  }
  return 0;
}

