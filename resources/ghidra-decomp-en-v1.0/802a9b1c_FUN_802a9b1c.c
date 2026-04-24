// Function: FUN_802a9b1c
// Entry: 802a9b1c
// Size: 240 bytes

undefined4 FUN_802a9b1c(int param_1,int param_2,int param_3)

{
  char cVar1;
  byte bVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  cVar1 = *(char *)(iVar3 + 0x8c8);
  if ((((cVar1 != 'H') && (cVar1 != 'G')) && (cVar1 != 'D')) && (*(int *)(iVar3 + 0x7f8) == 0)) {
    bVar2 = *(byte *)(iVar3 + 0x3f0);
    if ((((bVar2 >> 5 & 1) == 0) && ((bVar2 >> 2 & 1) == 0)) &&
       (((bVar2 >> 3 & 1) == 0 && ((*(byte *)(iVar3 + 0x3f4) >> 6 & 1) != 0)))) {
      if (param_3 == 0x2d) {
        if (*(short *)(*(int *)(iVar3 + 0x35c) + 4) < 2) {
          return 0;
        }
      }
      else if (*(short *)(*(int *)(iVar3 + 0x35c) + 4) < 1) {
        return 0;
      }
      iVar3 = (int)*(short *)(param_2 + 0x274);
      if (((iVar3 != 1) && (iVar3 != 2)) &&
         ((iVar3 != 0x2a && (((iVar3 != 0x2c && (1 < (iVar3 - 0x2eU & 0xffff))) && (iVar3 != 0x2d)))
          ))) {
        return 0;
      }
      return 1;
    }
  }
  return 0;
}

