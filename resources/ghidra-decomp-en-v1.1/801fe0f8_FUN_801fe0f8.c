// Function: FUN_801fe0f8
// Entry: 801fe0f8
// Size: 244 bytes

void FUN_801fe0f8(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined **)(param_1 + 0xbc) = &LAB_801fe040;
  *(undefined2 *)(iVar2 + 4) = 7000;
  *(undefined2 *)(iVar2 + 6) = 2000;
  if (*(short *)(param_2 + 0x1a) == 0) {
    *(undefined2 *)(param_2 + 0x1a) = 500;
  }
  uVar1 = FUN_80022264(600,1000);
  *(float *)(param_1 + 8) =
       FLOAT_803e6e00 /
       ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
               DOUBLE_803e6e40) /
       (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e6e40));
  *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 8);
  uVar1 = FUN_80022264(0x32,100);
  *(float *)(iVar2 + 0x10) =
       (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e6e40);
  return;
}

