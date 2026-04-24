// Function: FUN_801a8754
// Entry: 801a8754
// Size: 124 bytes

void FUN_801a8754(void)

{
  int iVar1;
  int iVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  iVar2 = (**(code **)(*DAT_803dd740 + 0xc))(iVar1,(int)in_r8);
  if (iVar2 != 0) {
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

