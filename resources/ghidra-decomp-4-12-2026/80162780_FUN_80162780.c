// Function: FUN_80162780
// Entry: 80162780
// Size: 580 bytes

/* WARNING: Removing unreachable block (ram,0x801629a0) */
/* WARNING: Removing unreachable block (ram,0x80162790) */

undefined4
FUN_80162780(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  undefined4 uVar2;
  int iVar3;
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
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,0);
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffffe;
    FUN_8000bb38(param_9,0x27b);
  }
  uStack_2c = *(char *)(iVar4 + 0x45) * -2 + 1U ^ 0x80000000;
  local_34[1] = 176.0;
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x28))
            ((double)(FLOAT_803e3bb0 *
                     *(float *)(param_10 + 0x2a0) *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e3b70)),
             *(int *)(iVar4 + 0x38),iVar4 + 0x48);
  if (FLOAT_803e3b8c <= *(float *)(iVar4 + 0x48)) {
    if (*(float *)(iVar4 + 0x48) <= FLOAT_803e3b90) {
      bVar1 = false;
    }
    else {
      *(float *)(iVar4 + 0x48) = FLOAT_803e3b90;
      bVar1 = true;
    }
  }
  else {
    *(float *)(iVar4 + 0x48) = FLOAT_803e3b8c;
    bVar1 = true;
  }
  if (bVar1) {
    uVar2 = 7;
  }
  else {
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
    iVar3 = FUN_80021884();
    *(short *)(param_9 + 2) = (short)iVar3 * ((short)((int)*(char *)(iVar4 + 0x45) << 1) + -1);
    uVar2 = 0;
  }
  return uVar2;
}

