// Function: FUN_80296a14
// Entry: 80296a14
// Size: 88 bytes

undefined4 FUN_80296a14(int param_1)

{
  byte bVar1;
  short sVar2;
  
  bVar1 = *(byte *)(*(int *)(param_1 + 0xb8) + 0x3f0);
  if ((((bVar1 >> 2 & 1) == 0) && ((bVar1 >> 3 & 1) == 0)) && ((bVar1 >> 4 & 1) == 0)) {
    sVar2 = *(short *)(*(int *)(param_1 + 0xb8) + 0x274);
    if ((sVar2 != 1) && (sVar2 != 2)) {
      return 0;
    }
    return 1;
  }
  return 0;
}

