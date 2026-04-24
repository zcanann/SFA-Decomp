// Function: FUN_80296328
// Entry: 80296328
// Size: 236 bytes

undefined4 FUN_80296328(int param_1)

{
  byte bVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if ((((((*(ushort *)(param_1 + 0xb0) & 0x1000) != 0) && (-1 < *(char *)(iVar4 + 0x3f2))) ||
       (bVar1 = *(byte *)(iVar4 + 0x3f0), (bVar1 >> 2 & 1) != 0)) ||
      (((bVar1 >> 3 & 1) != 0 || ((bVar1 >> 5 & 1) != 0)))) ||
     ((*(int *)(iVar4 + 0x7f8) != 0 || ((bVar1 >> 1 & 1) != 0)))) {
    return 0;
  }
  sVar2 = *(short *)(iVar4 + 0x274);
  if ((((sVar2 != 1) && (sVar2 != 2)) && (sVar2 != 0x26)) &&
     (((sVar2 != 0x18 ||
       ((iVar3 = FUN_8001ffb4(0x3e3), iVar3 == 0 &&
        (*(short *)(*(int *)(iVar4 + 0x7f0) + 0x46) != 0x416)))) && (*(int *)(iVar4 + 0x2d0) == 0)))
     ) {
    return 0;
  }
  return 1;
}

