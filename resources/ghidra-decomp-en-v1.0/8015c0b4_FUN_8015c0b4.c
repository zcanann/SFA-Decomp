// Function: FUN_8015c0b4
// Entry: 8015c0b4
// Size: 504 bytes

undefined4 FUN_8015c0b4(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) | 4;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6f) = 1;
  FUN_8003393c();
  if (*(char *)(param_2 + 0x27a) != '\0') {
    DAT_803dda79 = FUN_800221a0(0,2);
    iVar1 = FUN_800221a0(0,1);
    if (iVar1 == 0) {
      if (*(char *)(param_2 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e2d14,param_1,3,0);
        *(undefined *)(param_2 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e2d14,param_1,7,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    *(undefined *)(param_2 + 0x34d) = 1;
    *(float *)(param_2 + 0x2a0) =
         FLOAT_803e2d4c +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e2d08) /
         FLOAT_803e2d50;
  }
  if ((*(byte *)(iVar2 + 0x406) < 0x33) || ((*(byte *)(iVar2 + 0x404) & 2) != 0)) {
    *(float *)(param_2 + 0x280) = FLOAT_803e2d14;
  }
  else if ((*(float *)(param_2 + 0x2c0) <= FLOAT_803e2d54) || (*(char *)(param_2 + 0x346) != '\0'))
  {
    *(float *)(param_2 + 0x280) = FLOAT_803e2d14;
  }
  else {
    *(float *)(param_2 + 0x280) = *(float *)(param_2 + 0x2c0) / FLOAT_803e2d54 - FLOAT_803e2d48;
    *(float *)(param_2 + 0x280) =
         *(float *)(param_2 + 0x280) *
         ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e2d08) /
         FLOAT_803e2d58);
  }
  (**(code **)(*DAT_803dca8c + 0x30))((double)FLOAT_803db414,param_1,param_2,4);
  return 0;
}

