// Function: FUN_8027591c
// Entry: 8027591c
// Size: 168 bytes

int FUN_8027591c(undefined2 param_1)

{
  int iVar1;
  int iVar2;
  undefined2 *puVar3;
  
  iVar2 = 0;
  puVar3 = &DAT_803caad8;
  DAT_803caf04 = param_1;
  while( true ) {
    if ((int)(uint)DAT_803def12 <= iVar2) {
      return 0;
    }
    iVar1 = FUN_8028364c(&DAT_803caf04,*(int *)(puVar3 + 2),(uint)(ushort)puVar3[1],10,&LAB_8027590c
                        );
    if (iVar1 != 0) break;
    puVar3 = puVar3 + 4;
    iVar2 = iVar2 + 1;
  }
  return iVar1;
}

