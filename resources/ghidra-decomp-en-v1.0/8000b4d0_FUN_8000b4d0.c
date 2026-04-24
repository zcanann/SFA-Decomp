// Function: FUN_8000b4d0
// Entry: 8000b4d0
// Size: 168 bytes

int FUN_8000b4d0(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_8000ccec(0,0,param_2,3);
  if ((puVar1 != (undefined4 *)0x0) && (param_3 < DAT_803dc83c)) {
    FUN_80272868(*puVar1);
    *puVar1 = 0xffffffff;
  }
  if (DAT_803dc83c < param_3) {
    FUN_8000be60(param_1,0,0,param_2);
  }
  return DAT_803dc83c;
}

