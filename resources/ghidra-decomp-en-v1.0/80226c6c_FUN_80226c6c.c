// Function: FUN_80226c6c
// Entry: 80226c6c
// Size: 172 bytes

void FUN_80226c6c(int param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,9);
  cVar1 = *(char *)(iVar2 + 0xc);
  if (cVar1 == '\x01') {
    FUN_800200e8(0x7ef,0);
    FUN_800200e8(0x7ed,0);
    FUN_800200e8(0xba6,0);
    FUN_800200e8(0xedd,0);
  }
  else if (cVar1 == '\x02') {
    FUN_800200e8(0x7f0,0);
    FUN_800200e8(0x7ee,0);
    FUN_800200e8(0xba6,0);
    FUN_800200e8(0xedc,0);
  }
  FUN_8001467c();
  return;
}

