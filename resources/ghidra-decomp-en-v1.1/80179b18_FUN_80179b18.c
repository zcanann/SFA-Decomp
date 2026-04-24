// Function: FUN_80179b18
// Entry: 80179b18
// Size: 40 bytes

undefined4 FUN_80179b18(int param_1)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0x274);
  if ((cVar1 == '\x02') || (cVar1 == '\x01')) {
    uVar2 = 1;
  }
  return uVar2;
}

