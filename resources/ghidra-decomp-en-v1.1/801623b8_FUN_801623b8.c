// Function: FUN_801623b8
// Entry: 801623b8
// Size: 968 bytes

/* WARNING: Removing unreachable block (ram,0x8016275c) */
/* WARNING: Removing unreachable block (ram,0x801623c8) */

undefined4
FUN_801623b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  double dVar6;
  ushort local_58;
  undefined auStack_56 [2];
  ushort local_54 [2];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c [2];
  uint uStack_34;
  undefined8 local_30;
  
  iVar5 = *(int *)(*(int *)(param_9 + 0x5c) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,3,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b88;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,9);
  uStack_34 = *(char *)(iVar5 + 0x45) * -2 + 1U ^ 0x80000000;
  local_3c[1] = 176.0;
  (**(code **)(**(int **)(*(int *)(iVar5 + 0x38) + 0x68) + 0x28))
            ((double)(*(float *)(param_10 + 0x280) *
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e3b70)),
             *(int *)(iVar5 + 0x38),iVar5 + 0x48);
  if (FLOAT_803e3b8c <= *(float *)(iVar5 + 0x48)) {
    if (FLOAT_803e3b90 < *(float *)(iVar5 + 0x48)) {
      *(float *)(iVar5 + 0x48) = FLOAT_803e3b90;
    }
  }
  else {
    *(float *)(iVar5 + 0x48) = FLOAT_803e3b8c;
  }
  (**(code **)(**(int **)(*(int *)(iVar5 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar5 + 0x48) - FLOAT_803e3b94),*(int *)(iVar5 + 0x38),&local_50,
             &local_4c,&local_48);
  (**(code **)(**(int **)(*(int *)(iVar5 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e3b94 + *(float *)(iVar5 + 0x48)),*(int *)(iVar5 + 0x38),&local_44,
             &local_40,local_3c);
  local_50 = local_50 - local_44;
  local_4c = local_4c - local_40;
  local_48 = local_48 - local_3c[0];
  dVar6 = FUN_80293900((double)(local_50 * local_50 + local_48 * local_48));
  local_50 = (float)dVar6;
  iVar3 = FUN_80021884();
  uStack_34 = (int)(short)((short)iVar3 * ((short)((int)*(char *)(iVar5 + 0x45) << 1) + -1)) ^
              0x80000000;
  local_3c[1] = 176.0;
  iVar3 = (int)(-(FLOAT_803e3b98 * *(float *)(param_9 + 0x4c) - FLOAT_803e3b54) *
               (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e3b70));
  local_30 = (double)(longlong)iVar3;
  param_9[1] = (short)iVar3;
  if (*(char *)(param_10 + 0x346) == '\0') {
    uVar4 = 0;
  }
  else {
    (**(code **)(*DAT_803dd738 + 0x14))
              (param_9,*(undefined4 *)(param_10 + 0x2d0),0x10,local_54,auStack_56,&local_58);
    *(char *)(iVar5 + 0x45) = '\x01' - *(char *)(iVar5 + 0x45);
    uVar2 = countLeadingZeros((int)*(char *)(iVar5 + 0x45));
    *param_9 = *(short *)(iVar5 + 0x58) + (short)((uVar2 >> 5) << 0xf);
    uVar2 = FUN_80022264(0x32,100);
    local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    fVar1 = (float)((double)CONCAT44(0x43300000,*(char *)(iVar5 + 0x45) * 2 - 1U ^ 0x80000000) -
                   DOUBLE_803e3b70) * ((float)(local_30 - DOUBLE_803e3b70) / FLOAT_803e3b9c);
    if ((local_54[0] < 4) || (0xb < local_54[0])) {
      uVar2 = (uint)local_58;
      if (uVar2 < 0x1f5) {
        local_30 = (double)CONCAT44(0x43300000,uVar2);
        fVar1 = fVar1 * (FLOAT_803e3b54 + (float)(local_30 - DOUBLE_803e3ba8) / FLOAT_803e3ba0);
      }
      else {
        local_30 = (double)CONCAT44(0x43300000,uVar2);
        fVar1 = fVar1 * (FLOAT_803e3b54 + (float)(local_30 - DOUBLE_803e3ba8) / FLOAT_803e3b9c);
      }
    }
    *(float *)(iVar5 + 0x54) = *(float *)(iVar5 + 0x48) - fVar1;
    fVar1 = FLOAT_803e3b54;
    if (FLOAT_803e3b54 < *(float *)(iVar5 + 0x54)) {
      fVar1 = *(float *)(iVar5 + 0x54);
    }
    *(float *)(iVar5 + 0x54) = fVar1;
    fVar1 = FLOAT_803e3ba4;
    if (*(float *)(iVar5 + 0x54) < FLOAT_803e3ba4) {
      fVar1 = *(float *)(iVar5 + 0x54);
    }
    *(float *)(iVar5 + 0x54) = fVar1;
    uVar4 = 4;
  }
  return uVar4;
}

