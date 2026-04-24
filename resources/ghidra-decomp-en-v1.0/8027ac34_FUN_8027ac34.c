// Function: FUN_8027ac34
// Entry: 8027ac34
// Size: 132 bytes

undefined4 FUN_8027ac34(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  byte bVar2;
  
  bVar2 = 0;
  while( true ) {
    if (0xe < bVar2) {
      return 0;
    }
    iVar1 = FUN_8027aa94(param_1,param_2,param_3);
    if (iVar1 != 0) break;
    bVar2 = bVar2 + 1;
  }
  return 1;
}

