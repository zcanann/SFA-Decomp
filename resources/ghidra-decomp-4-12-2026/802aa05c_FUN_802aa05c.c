// Function: FUN_802aa05c
// Entry: 802aa05c
// Size: 272 bytes

undefined4 FUN_802aa05c(int param_1,int param_2)

{
  char cVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if (((((((*(short *)(param_2 + 0x274) == 1) || (*(short *)(param_2 + 0x274) == 2)) &&
         (iVar3 = *(int *)(iVar5 + 0x4b8), iVar3 != 0)) &&
        ((*(short *)(iVar3 + 0x46) == 0x414 && ((*(byte *)(iVar3 + 0xaf) & 4) != 0)))) &&
       (((*(byte *)(iVar3 + 0xaf) & 0x18) == 0 &&
        ((*(int *)(param_2 + 0x2d0) == 0 && (cVar1 = *(char *)(iVar5 + 0x8c8), cVar1 != 'H')))))) &&
      (cVar1 != 'G')) &&
     ((((cVar1 != 'D' && (*(int *)(iVar5 + 0x7f8) == 0)) &&
       (bVar2 = *(byte *)(iVar5 + 0x3f0), (bVar2 >> 5 & 1) == 0)) &&
      ((((bVar2 >> 2 & 1) == 0 && ((bVar2 >> 3 & 1) == 0)) &&
       (((*(byte *)(iVar5 + 0x3f4) >> 6 & 1) != 0 &&
        ((0x13 < *(short *)(*(int *)(iVar5 + 0x35c) + 4) &&
         (uVar4 = FUN_80020078(0x5bd), uVar4 != 0)))))))))) {
    return 1;
  }
  return 0;
}

