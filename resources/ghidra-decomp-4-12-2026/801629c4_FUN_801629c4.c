// Function: FUN_801629c4
// Entry: 801629c4
// Size: 724 bytes

/* WARNING: Removing unreachable block (ram,0x80162c74) */
/* WARNING: Removing unreachable block (ram,0x801629d4) */

undefined4
FUN_801629c4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  ushort local_48;
  undefined auStack_46 [2];
  ushort local_44 [2];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [2];
  uint uStack_24;
  
  iVar3 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b88;
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  uStack_24 = *(char *)(iVar3 + 0x45) * -2 + 1U ^ 0x80000000;
  local_2c[1] = 176.0;
  (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x28))
            ((double)(*(float *)(param_10 + 0x280) *
                     (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e3b70)),
             *(int *)(iVar3 + 0x38),iVar3 + 0x48);
  if (FLOAT_803e3b8c <= *(float *)(iVar3 + 0x48)) {
    if (FLOAT_803e3b90 < *(float *)(iVar3 + 0x48)) {
      *(float *)(iVar3 + 0x48) = FLOAT_803e3b90;
    }
  }
  else {
    *(float *)(iVar3 + 0x48) = FLOAT_803e3b8c;
  }
  (**(code **)(*DAT_803dd738 + 0x14))
            (param_9,*(undefined4 *)(param_10 + 0x2d0),0x10,local_44,auStack_46,&local_48);
  if ((((local_44[0] < 4) || (0xb < local_44[0])) || (local_48 < 0x191)) ||
     ((*(float *)(iVar3 + 0x48) <= FLOAT_803e3b98 || (FLOAT_803e3bb4 <= *(float *)(iVar3 + 0x48)))))
  {
    if (((int)*(char *)(iVar3 + 0x45) ==
         ((uint)(byte)((*(float *)(iVar3 + 0x54) <= *(float *)(iVar3 + 0x48)) << 1) << 0x1c) >> 0x1d
        ) || (*(char *)(param_10 + 0x346) == '\0')) {
      if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
        *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffffe;
        FUN_8000bb38(param_9,0x27b);
      }
      (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
                ((double)(*(float *)(iVar3 + 0x48) - FLOAT_803e3b94),*(int *)(iVar3 + 0x38),
                 &local_40,&local_3c,&local_38);
      (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
                ((double)(FLOAT_803e3b94 + *(float *)(iVar3 + 0x48)),*(int *)(iVar3 + 0x38),
                 &local_34,&local_30,local_2c);
      local_40 = local_40 - local_34;
      local_3c = local_3c - local_30;
      local_38 = local_38 - local_2c[0];
      dVar4 = FUN_80293900((double)(local_40 * local_40 + local_38 * local_38));
      local_40 = (float)dVar4;
      iVar2 = FUN_80021884();
      *(short *)(param_9 + 2) = (short)iVar2 * ((short)((int)*(char *)(iVar3 + 0x45) << 1) + -1);
      uVar1 = 0;
    }
    else {
      uVar1 = 3;
    }
  }
  else {
    uVar1 = 3;
  }
  return uVar1;
}

