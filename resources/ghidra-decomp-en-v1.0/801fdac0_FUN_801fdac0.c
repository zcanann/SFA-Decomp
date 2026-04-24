// Function: FUN_801fdac0
// Entry: 801fdac0
// Size: 244 bytes

void FUN_801fdac0(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined **)(param_1 + 0xbc) = &LAB_801fda08;
  *(undefined2 *)(iVar2 + 4) = 7000;
  *(undefined2 *)(iVar2 + 6) = 2000;
  if (*(short *)(param_2 + 0x1a) == 0) {
    *(undefined2 *)(param_2 + 0x1a) = 500;
  }
  uVar1 = FUN_800221a0(600,1000);
  *(float *)(param_1 + 8) =
       FLOAT_803e6168 /
       ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
               DOUBLE_803e61a8) /
       (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e61a8));
  *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 8);
  uVar1 = FUN_800221a0(0x32,100);
  *(float *)(iVar2 + 0x10) =
       (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e61a8);
  return;
}

