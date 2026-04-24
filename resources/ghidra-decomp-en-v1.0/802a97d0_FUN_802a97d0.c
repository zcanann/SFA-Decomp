// Function: FUN_802a97d0
// Entry: 802a97d0
// Size: 300 bytes

undefined4 FUN_802a97d0(int param_1,int param_2)

{
  char cVar1;
  byte bVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  sVar3 = *(short *)(param_2 + 0x274);
  if (((((((sVar3 == 1) || (sVar3 == 2)) || (sVar3 == 0x26)) &&
        ((iVar4 = FUN_8001ffb4(0x957), iVar4 != 0 && (iVar4 = *(int *)(iVar5 + 0x4b8), iVar4 != 0)))
        ) && ((*(short *)(iVar4 + 0x46) == 0x64f &&
              (((*(byte *)(iVar4 + 0xaf) & 4) != 0 && ((*(byte *)(iVar4 + 0xaf) & 0x18) == 0))))))
      && (*(int *)(param_2 + 0x2d0) == 0)) &&
     (((((cVar1 = *(char *)(iVar5 + 0x8c8), cVar1 != 'H' && (cVar1 != 'G')) && (cVar1 != 'D')) &&
       (((*(int *)(iVar5 + 0x7f8) == 0 && (bVar2 = *(byte *)(iVar5 + 0x3f0), (bVar2 >> 5 & 1) == 0))
        && (((bVar2 >> 2 & 1) == 0 &&
            (((bVar2 >> 3 & 1) == 0 && ((*(byte *)(iVar5 + 0x3f4) >> 6 & 1) != 0)))))))) &&
      (9 < *(short *)(*(int *)(*(int *)(param_1 + 0xb8) + 0x35c) + 4))))) {
    return 1;
  }
  return 0;
}

