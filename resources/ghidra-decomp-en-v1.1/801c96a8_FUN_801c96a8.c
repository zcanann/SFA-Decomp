// Function: FUN_801c96a8
// Entry: 801c96a8
// Size: 184 bytes

void FUN_801c96a8(void)

{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  iVar1 = FUN_8028683c();
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (in_r8 == '\0') {
    if (*piVar2 != 0) {
      FUN_8001dc30((double)FLOAT_803e5d70,*piVar2,'\0');
    }
  }
  else {
    if (*piVar2 != 0) {
      FUN_8001dc30((double)FLOAT_803e5d70,*piVar2,'\x01');
    }
    FUN_8003b9ec(iVar1);
    FUN_8009a010((double)FLOAT_803e5d70,(double)FLOAT_803e5d70,iVar1,7,(int *)*piVar2);
  }
  FUN_80286888();
  return;
}

