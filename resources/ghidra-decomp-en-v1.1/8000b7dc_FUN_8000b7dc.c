// Function: FUN_8000b7dc
// Entry: 8000b7dc
// Size: 104 bytes

void FUN_8000b7dc(int param_1,ushort param_2)

{
  uint *puVar1;
  
  if (((param_2 & 0xff) == 0) || (param_1 == 0)) {
    puVar1 = (uint *)0x0;
  }
  else {
    puVar1 = (uint *)FUN_8000cd0c(param_1,param_2,0,0);
  }
  if (puVar1 != (uint *)0x0) {
    FUN_80272fcc(*puVar1);
    *puVar1 = 0xffffffff;
  }
  return;
}

