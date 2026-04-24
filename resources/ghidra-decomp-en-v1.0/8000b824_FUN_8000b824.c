// Function: FUN_8000b824
// Entry: 8000b824
// Size: 100 bytes

void FUN_8000b824(undefined4 param_1,uint param_2)

{
  undefined4 *puVar1;
  
  if ((param_2 & 0xffff) == 0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puVar1 = (undefined4 *)FUN_8000ccec(param_1,0,param_2,0);
  }
  if (puVar1 != (undefined4 *)0x0) {
    FUN_80272868(*puVar1);
    *puVar1 = 0xffffffff;
  }
  return;
}

