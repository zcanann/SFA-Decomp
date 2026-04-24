// Function: FUN_801f3170
// Entry: 801f3170
// Size: 124 bytes

void FUN_801f3170(short *param_1)

{
  int iVar1;
  double dVar2;
  
  if (*(char *)(*(int *)(param_1 + 0x5c) + 0xc) == '\x02') {
    *param_1 = *param_1 + 0x32;
  }
  iVar1 = FUN_8002b9ec();
  dVar2 = (double)FUN_80021704(iVar1 + 0x18,param_1 + 0xc);
  if ((double)FLOAT_803e5de8 <= dVar2) {
    FUN_8000b7bc(param_1,0x40);
  }
  else {
    FUN_8000bb18(param_1,0x72);
  }
  return;
}

