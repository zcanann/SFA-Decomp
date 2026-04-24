// Function: FUN_80167ec4
// Entry: 80167ec4
// Size: 148 bytes

undefined4 FUN_80167ec4(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  
  if ((*(char *)(param_2 + 0x27a) != '\0') && (FUN_80035f20(), *(char *)(param_2 + 0x27a) != '\0'))
  {
    uVar1 = FUN_800221a0(6,7);
    FUN_80030334((double)FLOAT_803e3060,param_1,uVar1,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(float *)(param_2 + 0x2a0) = FLOAT_803e3094;
  *(undefined *)(param_2 + 0x34d) = 1;
  return 0;
}

