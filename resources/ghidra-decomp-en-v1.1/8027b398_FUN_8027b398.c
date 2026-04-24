// Function: FUN_8027b398
// Entry: 8027b398
// Size: 132 bytes

undefined4 FUN_8027b398(char *param_1,undefined2 *param_2,short *param_3)

{
  int iVar1;
  byte bVar2;
  
  bVar2 = 0;
  while( true ) {
    if (0xe < bVar2) {
      return 0;
    }
    iVar1 = FUN_8027b1f8(param_1,param_2,param_3);
    if (iVar1 != 0) break;
    bVar2 = bVar2 + 1;
  }
  return 1;
}

