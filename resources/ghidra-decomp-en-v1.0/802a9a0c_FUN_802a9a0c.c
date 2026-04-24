// Function: FUN_802a9a0c
// Entry: 802a9a0c
// Size: 272 bytes

undefined4 FUN_802a9a0c(int param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  short sVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar2 = FUN_8001ffb4(0xc55);
  if (iVar2 == 0) {
    sVar3 = 10;
  }
  else {
    sVar3 = 0x14;
  }
  iVar2 = FUN_8001ffb4(0x107);
  if ((((iVar2 != 0) && (sVar3 <= *(short *)(*(int *)(*(int *)(param_1 + 0xb8) + 0x35c) + 4))) &&
      (*(char *)(iVar4 + 0x8c8) != 'D')) &&
     (((*(int *)(iVar4 + 0x7f8) == 0 && (bVar1 = *(byte *)(iVar4 + 0x3f0), (bVar1 >> 5 & 1) == 0))
      && (((bVar1 >> 2 & 1) == 0 &&
          (((bVar1 >> 3 & 1) == 0 && ((*(byte *)(iVar4 + 0x3f4) >> 6 & 1) != 0)))))))) {
    sVar3 = *(short *)(param_2 + 0x274);
    if ((sVar3 != 1) && (((sVar3 != 2 && (sVar3 != 0x25)) && (sVar3 != 0x24)))) {
      return 0;
    }
    return 1;
  }
  return 0;
}

