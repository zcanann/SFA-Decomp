// Function: FUN_80161880
// Entry: 80161880
// Size: 632 bytes

/* WARNING: Removing unreachable block (ram,0x80161ad4) */

undefined4 FUN_80161880(undefined8 param_1,int param_2,int param_3)

{
  int iVar1;
  short sVar3;
  undefined4 uVar2;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f31;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = *(int *)(*(int *)(param_2 + 0xb8) + 0x40c);
  *(undefined *)(*(int *)(param_2 + 0x54) + 0x6e) = 9;
  *(undefined *)(*(int *)(param_2 + 0x54) + 0x6f) = 1;
  FUN_8003393c();
  iVar1 = FUN_800221a0(0,100);
  if (iVar1 < 0x32) {
    if (*(char *)(param_3 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e2eb8,param_2,1,0);
      *(undefined *)(param_3 + 0x346) = 0;
    }
  }
  else if (*(char *)(param_3 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2eb8,param_2,4,0);
    *(undefined *)(param_3 + 0x346) = 0;
  }
  *(float *)(param_3 + 0x2a0) = FLOAT_803e2ef0;
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
  uStack44 = *(char *)(iVar4 + 0x45) * -2 + 1U ^ 0x80000000;
  local_30 = 0x43300000;
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x28))
            ((double)(*(float *)(param_3 + 0x280) *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e2ed8)),
             *(int *)(iVar4 + 0x38),iVar4 + 0x48);
  if (FLOAT_803e2ef4 <= *(float *)(iVar4 + 0x48)) {
    if (FLOAT_803e2ef8 < *(float *)(iVar4 + 0x48)) {
      *(float *)(iVar4 + 0x48) = FLOAT_803e2ef8;
    }
  }
  else {
    *(float *)(iVar4 + 0x48) = FLOAT_803e2ef4;
  }
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar4 + 0x48) - FLOAT_803e2efc),*(int *)(iVar4 + 0x38),&local_48,
             &local_44,&local_40);
  (**(code **)(**(int **)(*(int *)(iVar4 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e2efc + *(float *)(iVar4 + 0x48)),*(int *)(iVar4 + 0x38),&local_3c,
             &local_38,&local_34);
  local_48 = local_48 - local_3c;
  local_44 = local_44 - local_38;
  local_40 = local_40 - local_34;
  dVar6 = (double)FUN_802931a0((double)(local_48 * local_48 + local_40 * local_40));
  local_48 = (float)dVar6;
  sVar3 = FUN_800217c0((double)local_44,(double)(float)dVar6);
  *(short *)(param_2 + 2) = sVar3 * ((short)((int)*(char *)(iVar4 + 0x45) << 1) + -1);
  if (*(char *)(param_3 + 0x346) == '\0') {
    uVar2 = 0;
  }
  else {
    uVar2 = 5;
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return uVar2;
}

