// Function: FUN_802a9f30
// Entry: 802a9f30
// Size: 300 bytes

undefined4 FUN_802a9f30(int param_1,int param_2)

{
  char cVar1;
  byte bVar2;
  short sVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  iVar6 = *(int *)(param_1 + 0xb8);
  sVar3 = *(short *)(param_2 + 0x274);
  if (((((((sVar3 == 1) || (sVar3 == 2)) || (sVar3 == 0x26)) &&
        ((uVar4 = FUN_80020078(0x957), uVar4 != 0 && (iVar5 = *(int *)(iVar6 + 0x4b8), iVar5 != 0)))
        ) && ((*(short *)(iVar5 + 0x46) == 0x64f &&
              (((*(byte *)(iVar5 + 0xaf) & 4) != 0 && ((*(byte *)(iVar5 + 0xaf) & 0x18) == 0))))))
      && (*(int *)(param_2 + 0x2d0) == 0)) &&
     (((((cVar1 = *(char *)(iVar6 + 0x8c8), cVar1 != 'H' && (cVar1 != 'G')) && (cVar1 != 'D')) &&
       (((*(int *)(iVar6 + 0x7f8) == 0 && (bVar2 = *(byte *)(iVar6 + 0x3f0), (bVar2 >> 5 & 1) == 0))
        && (((bVar2 >> 2 & 1) == 0 &&
            (((bVar2 >> 3 & 1) == 0 && ((*(byte *)(iVar6 + 0x3f4) >> 6 & 1) != 0)))))))) &&
      (9 < *(short *)(*(int *)(*(int *)(param_1 + 0xb8) + 0x35c) + 4))))) {
    return 1;
  }
  return 0;
}

