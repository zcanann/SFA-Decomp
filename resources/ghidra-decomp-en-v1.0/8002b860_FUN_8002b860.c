// Function: FUN_8002b860
// Entry: 8002b860
// Size: 36 bytes

void FUN_8002b860(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = (int)DAT_803dcb74;
  DAT_803dcb74 = DAT_803dcb74 + '\x01';
  (&DAT_803408a8)[iVar1] = param_1;
  return;
}

