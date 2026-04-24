// Function: FUN_802751b8
// Entry: 802751b8
// Size: 168 bytes

int FUN_802751b8(undefined2 param_1)

{
  int iVar1;
  int iVar2;
  undefined2 *puVar3;
  
  iVar2 = 0;
  puVar3 = &DAT_803c9e78;
  DAT_803ca2a4 = param_1;
  while( true ) {
    if ((int)(uint)DAT_803de292 <= iVar2) {
      return 0;
    }
    iVar1 = FUN_80282ee8(&DAT_803ca2a4,*(undefined4 *)(puVar3 + 2),puVar3[1],10,&LAB_802751a8);
    if (iVar1 != 0) break;
    puVar3 = puVar3 + 4;
    iVar2 = iVar2 + 1;
  }
  return iVar1;
}

