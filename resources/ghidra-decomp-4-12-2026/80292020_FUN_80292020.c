// Function: FUN_80292020
// Entry: 80292020
// Size: 136 bytes

/* WARNING: Removing unreachable block (ram,0x80292058) */

int FUN_80292020(int param_1,int param_2)

{
  byte bVar1;
  byte bVar2;
  
  if ((param_1 == 0) || ((*(ushort *)(param_1 + 4) >> 6 & 7) == 0)) {
    return 0;
  }
  bVar1 = *(byte *)(param_1 + 5);
  bVar2 = bVar1 >> 4 & 3;
  if (bVar2 == 1) {
    return -1;
  }
  if (bVar2 != 0) {
    if (bVar2 < 3) {
      return 1;
    }
    return param_1;
  }
  if (param_2 < 1) {
    if (param_2 < 0) {
      *(byte *)(param_1 + 5) = bVar1 & 0xcf | 0x10;
    }
  }
  else {
    *(byte *)(param_1 + 5) = bVar1 & 0xcf | 0x20;
  }
  return param_2;
}

