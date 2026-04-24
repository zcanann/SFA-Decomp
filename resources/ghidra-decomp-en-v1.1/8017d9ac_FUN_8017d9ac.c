// Function: FUN_8017d9ac
// Entry: 8017d9ac
// Size: 784 bytes

void FUN_8017d9ac(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  int local_28;
  int local_24;
  float local_20 [5];
  
  uVar4 = *(undefined4 *)(param_1 + 0xb8);
  local_20[0] = FLOAT_803e4454;
  iVar1 = (**(code **)(*DAT_803dd740 + 8))(param_1,*(undefined4 *)(param_1 + 0xb8));
  if (iVar1 == 0) {
    if ((*(uint *)(param_1 + 0xf4) & 1) != 0) {
      iVar1 = FUN_8002e1f4(&local_24,&local_28);
      for (; local_24 < local_28; local_24 = local_24 + 1) {
        iVar3 = *(int *)(iVar1 + local_24 * 4);
        if (((iVar3 != param_1) && (*(short *)(iVar3 + 0x46) == 499)) &&
           (dVar5 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18)),
           dVar5 < (double)FLOAT_803e4458)) {
          iVar3 = *(int *)(*(int *)(iVar1 + local_24 * 4) + 0x4c);
          if ((int)*(short *)(param_1 + 0x46) == *(char *)(iVar3 + 0x19) + 500) {
            if ((int)*(short *)(iVar3 + 0x1e) != 0xffffffff) {
              FUN_800201ac((int)*(short *)(iVar3 + 0x1e),1);
            }
          }
          else if ((int)*(short *)(iVar3 + 0x1e) != 0xffffffff) {
            FUN_800201ac((int)*(short *)(iVar3 + 0x1e),0);
          }
          *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0xc);
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0x10);
          *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0x14);
        }
      }
    }
    iVar1 = FUN_8002bac4();
    uVar2 = FUN_802979fc(iVar1);
    if ((uVar2 & 0x4000) == 0) {
      (**(code **)(*DAT_803dd740 + 0x24))(uVar4,1);
      *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) & 0xfffffffd;
    }
    else {
      (**(code **)(*DAT_803dd740 + 0x24))(uVar4,0);
      *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 2;
    }
    *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) & 0xfffffffe;
  }
  else {
    if ((*(uint *)(param_1 + 0xf4) & 2) != 0) {
      iVar1 = FUN_8002e1f4(&local_24,&local_28);
      for (; local_24 < local_28; local_24 = local_24 + 1) {
        iVar3 = *(int *)(iVar1 + local_24 * 4);
        if (((iVar3 != param_1) && (*(short *)(iVar3 + 0x46) == 499)) &&
           ((dVar5 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18)),
            dVar5 < (double)FLOAT_803e4458 &&
            (uVar2 = (uint)*(short *)(*(int *)(*(int *)(iVar1 + local_24 * 4) + 0x4c) + 0x1e),
            uVar2 != 0xffffffff)))) {
          FUN_800201ac(uVar2,0);
        }
      }
    }
    iVar1 = FUN_8002bac4();
    FUN_80036f50(0x10,param_1,local_20);
    uVar2 = FUN_802979fc(iVar1);
    if (((uVar2 & 0x4000) == 0) || (local_20[0] <= FLOAT_803e445c)) {
      (**(code **)(*DAT_803dd740 + 0x24))(uVar4,1);
    }
    else {
      (**(code **)(*DAT_803dd740 + 0x24))(uVar4,0);
      FUN_8011f6d0(5);
      *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 1;
    }
    *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) & 0xfffffffd;
  }
  return;
}

