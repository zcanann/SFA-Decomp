// Function: FUN_80162518
// Entry: 80162518
// Size: 724 bytes

/* WARNING: Removing unreachable block (ram,0x801627c8) */

undefined4 FUN_80162518(undefined8 param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  short sVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f31;
  ushort local_48;
  undefined auStack70 [2];
  ushort local_44 [2];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = *(int *)(*(int *)(param_2 + 0xb8) + 0x40c);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2eb8,param_2,0,0);
    *(undefined *)(param_3 + 0x346) = 0;
  }
  *(float *)(param_3 + 0x2a0) = FLOAT_803e2ef0;
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
  uStack36 = *(char *)(iVar3 + 0x45) * -2 + 1U ^ 0x80000000;
  local_28 = 0x43300000;
  (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x28))
            ((double)(*(float *)(param_3 + 0x280) *
                     (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e2ed8)),
             *(int *)(iVar3 + 0x38),iVar3 + 0x48);
  if (FLOAT_803e2ef4 <= *(float *)(iVar3 + 0x48)) {
    if (FLOAT_803e2ef8 < *(float *)(iVar3 + 0x48)) {
      *(float *)(iVar3 + 0x48) = FLOAT_803e2ef8;
    }
  }
  else {
    *(float *)(iVar3 + 0x48) = FLOAT_803e2ef4;
  }
  (**(code **)(*DAT_803dcab8 + 0x14))
            (param_2,*(undefined4 *)(param_3 + 0x2d0),0x10,local_44,auStack70,&local_48);
  if ((((local_44[0] < 4) || (0xb < local_44[0])) || (local_48 < 0x191)) ||
     ((*(float *)(iVar3 + 0x48) <= FLOAT_803e2f00 || (FLOAT_803e2f1c <= *(float *)(iVar3 + 0x48)))))
  {
    if (((int)*(char *)(iVar3 + 0x45) ==
         ((uint)(byte)((*(float *)(iVar3 + 0x54) <= *(float *)(iVar3 + 0x48)) << 1) << 0x1c) >> 0x1d
        ) || (*(char *)(param_3 + 0x346) == '\0')) {
      if ((*(uint *)(param_3 + 0x314) & 1) != 0) {
        *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xfffffffe;
        FUN_8000bb18(param_2,0x27b);
      }
      (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
                ((double)(*(float *)(iVar3 + 0x48) - FLOAT_803e2efc),*(int *)(iVar3 + 0x38),
                 &local_40,&local_3c,&local_38);
      (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
                ((double)(FLOAT_803e2efc + *(float *)(iVar3 + 0x48)),*(int *)(iVar3 + 0x38),
                 &local_34,&local_30,&local_2c);
      local_40 = local_40 - local_34;
      local_3c = local_3c - local_30;
      local_38 = local_38 - local_2c;
      dVar5 = (double)FUN_802931a0((double)(local_40 * local_40 + local_38 * local_38));
      local_40 = (float)dVar5;
      sVar2 = FUN_800217c0((double)local_3c,(double)(float)dVar5);
      *(short *)(param_2 + 2) = sVar2 * ((short)((int)*(char *)(iVar3 + 0x45) << 1) + -1);
      uVar1 = 0;
    }
    else {
      uVar1 = 3;
    }
  }
  else {
    uVar1 = 3;
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return uVar1;
}

