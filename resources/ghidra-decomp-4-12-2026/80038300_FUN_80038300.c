// Function: FUN_80038300
// Entry: 80038300
// Size: 120 bytes

undefined4 FUN_80038300(int param_1)

{
  int *piVar1;
  int local_18;
  int local_14 [4];
  
  piVar1 = (int *)FUN_8002e1f4(local_14,&local_18);
  local_14[0] = 0;
  while( true ) {
    if (local_18 <= local_14[0]) {
      return 0;
    }
    if (*piVar1 == param_1) break;
    piVar1 = piVar1 + 1;
    local_14[0] = local_14[0] + 1;
  }
  return 1;
}

