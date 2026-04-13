// Function: FUN_801eb0f8
// Entry: 801eb0f8
// Size: 908 bytes

uint FUN_801eb0f8(undefined2 *param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined2 uVar4;
  double dVar5;
  float local_18 [3];
  
  if ((*(byte *)(param_2 + 0x428) >> 3 & 1) == 0) {
    uVar2 = 0;
  }
  else {
    iVar3 = FUN_8005b478((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8));
    fVar1 = FLOAT_803e6780;
    if (iVar3 < 0) {
      dVar5 = FUN_801eacb0((int)param_1,param_2);
      iVar3 = (**(code **)(*DAT_803dd6ec + 0x18))
                        ((double)(float)((double)FLOAT_803dc074 * dVar5),param_2,param_2 + 0x28,
                         *(undefined *)(param_2 + 0x5d),1,0);
      (**(code **)(*DAT_803dd6ec + 0x14))(param_1,param_2 + 0x28);
      (**(code **)(*DAT_803dd6ec + 0x2c))(param_2 + 0x28);
      if (iVar3 == 0) {
        iVar3 = FUN_80021884();
        *param_1 = (short)iVar3;
        *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_2 + 0xc);
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 0x10);
        *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_2 + 0x14);
        (**(code **)(*DAT_803dd728 + 0x20))(param_1,param_2 + 0x178);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x10) = *(undefined4 *)(param_1 + 6);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x14) = *(undefined4 *)(param_1 + 8);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x18) = *(undefined4 *)(param_1 + 10);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x1c) = *(undefined4 *)(param_1 + 0xc);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x20) = *(undefined4 *)(param_1 + 0xe);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x24) = *(undefined4 *)(param_1 + 0x10);
        *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xfe;
        uVar2 = 0;
      }
      else {
        uVar2 = 0;
      }
    }
    else if ((*(byte *)(param_2 + 0x428) & 1) == 0) {
      *(float *)(param_2 + 0x494) = FLOAT_803e6780;
      *(float *)(param_2 + 0x498) = fVar1;
      dVar5 = FUN_801eacb0((int)param_1,param_2);
      *(float *)(param_2 + 0x49c) = (float)-dVar5;
      iVar3 = (**(code **)(*DAT_803dd6ec + 0x18))
                        ((double)(-*(float *)(param_2 + 0x49c) * FLOAT_803dc074),param_2,
                         param_2 + 0x28,*(undefined *)(param_2 + 0x5d),1,0);
      (**(code **)(*DAT_803dd6ec + 0x14))(param_1,param_2 + 0x28);
      (**(code **)(*DAT_803dd6ec + 0x2c))(param_2 + 0x28);
      if (iVar3 == 0) {
        FUN_801ecea8(param_1,param_2);
        iVar3 = FUN_80021884();
        uVar4 = (undefined2)iVar3;
        *param_1 = uVar4;
        *(undefined2 *)(param_2 + 0x40e) = uVar4;
        *(undefined2 *)(param_2 + 0x40c) = uVar4;
        *(float *)(param_2 + 0x430) = FLOAT_803e680c;
        *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_2 + 0xc);
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 0x10);
        *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_2 + 0x14);
        (**(code **)(*DAT_803dd728 + 0x20))(param_1,param_2 + 0x178);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x10) = *(undefined4 *)(param_1 + 6);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x14) = *(undefined4 *)(param_1 + 8);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x18) = *(undefined4 *)(param_1 + 10);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x1c) = *(undefined4 *)(param_1 + 0xc);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x20) = *(undefined4 *)(param_1 + 0xe);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x24) = *(undefined4 *)(param_1 + 0x10);
        if (*(char *)(param_2 + 0x434) == '\0') {
          FUN_80065a20((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                       (double)*(float *)(param_1 + 10),param_1,local_18,0);
          *(float *)(param_1 + 8) = *(float *)(param_1 + 8) - local_18[0];
          *(float *)(param_1 + 8) = *(float *)(param_1 + 8) + FLOAT_803e6810;
        }
        *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xfe | 1;
        uVar2 = 0;
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = FUN_801eae8c((int)param_1,param_2);
      uVar2 = (-uVar2 | uVar2) >> 0x1f;
    }
  }
  return uVar2;
}

