// Function: FUN_8000b4f0
// Entry: 8000b4f0
// Size: 168 bytes

int FUN_8000b4f0(uint param_1,ushort param_2,int param_3)

{
  uint *puVar1;
  
  puVar1 = (uint *)FUN_8000cd0c(0,0,param_2,3);
  if ((puVar1 != (uint *)0x0) && (param_3 < DAT_803dd4bc)) {
    FUN_80272fcc(*puVar1);
    *puVar1 = 0xffffffff;
  }
  if (DAT_803dd4bc < param_3) {
    FUN_8000be80(param_1,(float *)0x0,0,param_2);
  }
  return DAT_803dd4bc;
}

