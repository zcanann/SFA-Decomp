// Function: FUN_802a98fc
// Entry: 802a98fc
// Size: 272 bytes

undefined4 FUN_802a98fc(int param_1,int param_2)

{
  char cVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (((((((*(short *)(param_2 + 0x274) == 1) || (*(short *)(param_2 + 0x274) == 2)) &&
         (iVar3 = *(int *)(iVar4 + 0x4b8), iVar3 != 0)) &&
        ((*(short *)(iVar3 + 0x46) == 0x414 && ((*(byte *)(iVar3 + 0xaf) & 4) != 0)))) &&
       (((*(byte *)(iVar3 + 0xaf) & 0x18) == 0 &&
        ((*(int *)(param_2 + 0x2d0) == 0 && (cVar1 = *(char *)(iVar4 + 0x8c8), cVar1 != 'H')))))) &&
      (cVar1 != 'G')) &&
     ((((cVar1 != 'D' && (*(int *)(iVar4 + 0x7f8) == 0)) &&
       (bVar2 = *(byte *)(iVar4 + 0x3f0), (bVar2 >> 5 & 1) == 0)) &&
      ((((bVar2 >> 2 & 1) == 0 && ((bVar2 >> 3 & 1) == 0)) &&
       (((*(byte *)(iVar4 + 0x3f4) >> 6 & 1) != 0 &&
        ((0x13 < *(short *)(*(int *)(iVar4 + 0x35c) + 4) &&
         (iVar4 = FUN_8001ffb4(0x5bd), iVar4 != 0)))))))))) {
    return 1;
  }
  return 0;
}

