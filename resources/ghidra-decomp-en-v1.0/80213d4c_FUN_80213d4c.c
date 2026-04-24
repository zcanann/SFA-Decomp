// Function: FUN_80213d4c
// Entry: 80213d4c
// Size: 84 bytes

undefined4 FUN_80213d4c(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e67b8,param_1,0,0);
  }
  *(float *)(param_2 + 0x2a0) = FLOAT_803e6808;
  return 0;
}

