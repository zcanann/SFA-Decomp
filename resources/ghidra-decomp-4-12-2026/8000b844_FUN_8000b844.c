// Function: FUN_8000b844
// Entry: 8000b844
// Size: 100 bytes

void FUN_8000b844(int param_1,short param_2)

{
  uint *puVar1;
  
  if (param_2 == 0) {
    puVar1 = (uint *)0x0;
  }
  else {
    puVar1 = (uint *)FUN_8000cd0c(param_1,0,param_2,0);
  }
  if (puVar1 != (uint *)0x0) {
    FUN_80272fcc(*puVar1);
    *puVar1 = 0xffffffff;
  }
  return;
}

