// Function: FUN_8000a1d8
// Entry: 8000a1d8
// Size: 72 bytes

int FUN_8000a1d8(int param_1)

{
  int iVar1;
  
  if (param_1 == 0x2dc0) {
    iVar1 = FUN_80023d8c(0x2ec0,0xb);
    iVar1 = iVar1 + 0x100;
  }
  else {
    iVar1 = FUN_80023d8c(param_1,0xb);
  }
  return iVar1;
}

