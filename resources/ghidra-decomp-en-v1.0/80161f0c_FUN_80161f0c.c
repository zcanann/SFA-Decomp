// Function: FUN_80161f0c
// Entry: 80161f0c
// Size: 968 bytes

/* WARNING: Removing unreachable block (ram,0x801622b0) */

undefined4 FUN_80161f0c(undefined8 param_1,short *param_2,int param_3)

{
  int iVar1;
  float fVar2;
  uint uVar3;
  short sVar5;
  undefined4 uVar4;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  ushort local_58;
  undefined auStack86 [2];
  ushort local_54 [2];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack52;
  double local_30;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar6 = *(int *)(*(int *)(param_2 + 0x5c) + 0x40c);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2eb8,param_2,3,0);
    *(undefined *)(param_3 + 0x346) = 0;
  }
  *(float *)(param_3 + 0x2a0) = FLOAT_803e2ef0;
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,9);
  uStack52 = *(char *)(iVar6 + 0x45) * -2 + 1U ^ 0x80000000;
  local_38 = 0x43300000;
  (**(code **)(**(int **)(*(int *)(iVar6 + 0x38) + 0x68) + 0x28))
            ((double)(*(float *)(param_3 + 0x280) *
                     (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e2ed8)),
             *(int *)(iVar6 + 0x38),iVar6 + 0x48);
  if (FLOAT_803e2ef4 <= *(float *)(iVar6 + 0x48)) {
    if (FLOAT_803e2ef8 < *(float *)(iVar6 + 0x48)) {
      *(float *)(iVar6 + 0x48) = FLOAT_803e2ef8;
    }
  }
  else {
    *(float *)(iVar6 + 0x48) = FLOAT_803e2ef4;
  }
  (**(code **)(**(int **)(*(int *)(iVar6 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar6 + 0x48) - FLOAT_803e2efc),*(int *)(iVar6 + 0x38),&local_50,
             &local_4c,&local_48);
  (**(code **)(**(int **)(*(int *)(iVar6 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e2efc + *(float *)(iVar6 + 0x48)),*(int *)(iVar6 + 0x38),&local_44,
             &local_40,&local_3c);
  local_50 = local_50 - local_44;
  local_4c = local_4c - local_40;
  local_48 = local_48 - local_3c;
  dVar8 = (double)FUN_802931a0((double)(local_50 * local_50 + local_48 * local_48));
  local_50 = (float)dVar8;
  sVar5 = FUN_800217c0((double)local_4c,(double)(float)dVar8);
  uStack52 = (int)(short)(sVar5 * ((short)((int)*(char *)(iVar6 + 0x45) << 1) + -1)) ^ 0x80000000;
  local_38 = 0x43300000;
  iVar1 = (int)(-(FLOAT_803e2f00 * *(float *)(param_2 + 0x4c) - FLOAT_803e2ebc) *
               (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e2ed8));
  local_30 = (double)(longlong)iVar1;
  param_2[1] = (short)iVar1;
  if (*(char *)(param_3 + 0x346) == '\0') {
    uVar4 = 0;
  }
  else {
    (**(code **)(*DAT_803dcab8 + 0x14))
              (param_2,*(undefined4 *)(param_3 + 0x2d0),0x10,local_54,auStack86,&local_58);
    *(char *)(iVar6 + 0x45) = '\x01' - *(char *)(iVar6 + 0x45);
    uVar3 = countLeadingZeros((int)*(char *)(iVar6 + 0x45));
    *param_2 = *(short *)(iVar6 + 0x58) + (short)((uVar3 >> 5) << 0xf);
    uVar3 = FUN_800221a0(0x32,100);
    local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
    fVar2 = (float)((double)CONCAT44(0x43300000,*(char *)(iVar6 + 0x45) * 2 - 1U ^ 0x80000000) -
                   DOUBLE_803e2ed8) * ((float)(local_30 - DOUBLE_803e2ed8) / FLOAT_803e2f04);
    if ((local_54[0] < 4) || (0xb < local_54[0])) {
      uVar3 = (uint)local_58;
      if (uVar3 < 0x1f5) {
        local_30 = (double)CONCAT44(0x43300000,uVar3);
        fVar2 = fVar2 * (FLOAT_803e2ebc + (float)(local_30 - DOUBLE_803e2f10) / FLOAT_803e2f08);
      }
      else {
        local_30 = (double)CONCAT44(0x43300000,uVar3);
        fVar2 = fVar2 * (FLOAT_803e2ebc + (float)(local_30 - DOUBLE_803e2f10) / FLOAT_803e2f04);
      }
    }
    *(float *)(iVar6 + 0x54) = *(float *)(iVar6 + 0x48) - fVar2;
    fVar2 = FLOAT_803e2ebc;
    if (FLOAT_803e2ebc < *(float *)(iVar6 + 0x54)) {
      fVar2 = *(float *)(iVar6 + 0x54);
    }
    *(float *)(iVar6 + 0x54) = fVar2;
    fVar2 = FLOAT_803e2f0c;
    if (*(float *)(iVar6 + 0x54) < FLOAT_803e2f0c) {
      fVar2 = *(float *)(iVar6 + 0x54);
    }
    *(float *)(iVar6 + 0x54) = fVar2;
    uVar4 = 4;
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return uVar4;
}

