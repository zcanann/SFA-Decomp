// Function: FUN_80161d2c
// Entry: 80161d2c
// Size: 632 bytes

/* WARNING: Removing unreachable block (ram,0x80161f80) */
/* WARNING: Removing unreachable block (ram,0x80161d3c) */

undefined4
FUN_80161d2c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  double dVar5;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34 [2];
  uint uStack_2c;
  
  iVar4 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 9;
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
  FUN_80033a34(param_9);
  uVar1 = FUN_80022264(0,100);
  if ((int)uVar1 < 0x32) {
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
  }
  else if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b88;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  uStack_2c = *(char *)(iVar4 + 0x45) * -2 + 1U ^ 0x80000000;
  local_34[1] = 176.0;
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x28))
            ((double)(*(float *)(param_10 + 0x280) *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e3b70)),
             *(int *)(iVar4 + 0x38),iVar4 + 0x48);
  if (FLOAT_803e3b8c <= *(float *)(iVar4 + 0x48)) {
    if (FLOAT_803e3b90 < *(float *)(iVar4 + 0x48)) {
      *(float *)(iVar4 + 0x48) = FLOAT_803e3b90;
    }
  }
  else {
    *(float *)(iVar4 + 0x48) = FLOAT_803e3b8c;
  }
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar4 + 0x48) - FLOAT_803e3b94),*(int *)(iVar4 + 0x38),&local_48,
             &local_44,&local_40);
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e3b94 + *(float *)(iVar4 + 0x48)),*(int *)(iVar4 + 0x38),&local_3c,
             &local_38,local_34);
  local_48 = local_48 - local_3c;
  local_44 = local_44 - local_38;
  local_40 = local_40 - local_34[0];
  dVar5 = FUN_80293900((double)(local_48 * local_48 + local_40 * local_40));
  local_48 = (float)dVar5;
  iVar2 = FUN_80021884();
  *(short *)(param_9 + 2) = (short)iVar2 * ((short)((int)*(char *)(iVar4 + 0x45) << 1) + -1);
  if (*(char *)(param_10 + 0x346) == '\0') {
    uVar3 = 0;
  }
  else {
    uVar3 = 5;
  }
  return uVar3;
}

