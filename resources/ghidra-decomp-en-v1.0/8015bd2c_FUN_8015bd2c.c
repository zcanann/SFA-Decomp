// Function: FUN_8015bd2c
// Entry: 8015bd2c
// Size: 220 bytes

undefined4 FUN_8015bd2c(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2d14,param_1,0,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_8002b9ec();
    iVar1 = FUN_8002b9ec();
    if (*(short *)(iVar1 + 0x46) == 0) {
      FUN_8000bb18(param_1,0x239);
    }
    else {
      FUN_8000bb18(param_1,0x1f2);
    }
    FUN_8000bb18(param_1,0x26e);
  }
  *(undefined *)(param_2 + 0x34d) = 3;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2d34;
  *(float *)(param_2 + 0x280) = FLOAT_803e2d14;
  return 0;
}

