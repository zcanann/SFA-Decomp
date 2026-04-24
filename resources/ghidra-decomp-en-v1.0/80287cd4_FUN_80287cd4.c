// Function: FUN_80287cd4
// Entry: 80287cd4
// Size: 136 bytes

void FUN_80287cd4(char *param_1)

{
  char cVar1;
  undefined4 uVar2;
  char local_18;
  undefined local_17;
  
  while( true ) {
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    if (cVar1 == '\0') break;
    uVar2 = FUN_8028a648();
    local_17 = 0;
    local_18 = cVar1;
    FUN_8028a63c(0);
    FUN_8007d6dc(&local_18);
    FUN_8028a63c(uVar2);
  }
  return;
}

