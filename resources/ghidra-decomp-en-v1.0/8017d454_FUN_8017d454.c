// Function: FUN_8017d454
// Entry: 8017d454
// Size: 784 bytes

void FUN_8017d454(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  int local_28;
  int local_24;
  float local_20 [5];
  
  uVar5 = *(undefined4 *)(param_1 + 0xb8);
  local_20[0] = FLOAT_803e37bc;
  iVar1 = (**(code **)(*DAT_803dcac0 + 8))(param_1,*(undefined4 *)(param_1 + 0xb8));
  if (iVar1 == 0) {
    if ((*(uint *)(param_1 + 0xf4) & 1) != 0) {
      iVar1 = FUN_8002e0fc(&local_24,&local_28);
      for (; local_24 < local_28; local_24 = local_24 + 1) {
        iVar4 = *(int *)(iVar1 + local_24 * 4);
        if (((iVar4 != param_1) && (*(short *)(iVar4 + 0x46) == 499)) &&
           (dVar6 = (double)FUN_80021704(param_1 + 0x18,iVar4 + 0x18),
           dVar6 < (double)FLOAT_803e37c0)) {
          iVar4 = *(int *)(*(int *)(iVar1 + local_24 * 4) + 0x4c);
          if ((int)*(short *)(param_1 + 0x46) == *(char *)(iVar4 + 0x19) + 500) {
            if (*(short *)(iVar4 + 0x1e) != -1) {
              FUN_800200e8((int)*(short *)(iVar4 + 0x1e),1);
            }
          }
          else if (*(short *)(iVar4 + 0x1e) != -1) {
            FUN_800200e8((int)*(short *)(iVar4 + 0x1e),0);
          }
          *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0xc);
          *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0x10);
          *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*(int *)(iVar1 + local_24 * 4) + 0x14);
        }
      }
    }
    FUN_8002b9ec();
    uVar3 = FUN_8029729c();
    if ((uVar3 & 0x4000) == 0) {
      (**(code **)(*DAT_803dcac0 + 0x24))(uVar5,1);
      *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) & 0xfffffffd;
    }
    else {
      (**(code **)(*DAT_803dcac0 + 0x24))(uVar5,0);
      *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 2;
    }
    *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) & 0xfffffffe;
  }
  else {
    if ((*(uint *)(param_1 + 0xf4) & 2) != 0) {
      iVar1 = FUN_8002e0fc(&local_24,&local_28);
      for (; local_24 < local_28; local_24 = local_24 + 1) {
        iVar4 = *(int *)(iVar1 + local_24 * 4);
        if (((iVar4 != param_1) && (*(short *)(iVar4 + 0x46) == 499)) &&
           ((dVar6 = (double)FUN_80021704(param_1 + 0x18,iVar4 + 0x18),
            dVar6 < (double)FLOAT_803e37c0 &&
            (iVar4 = (int)*(short *)(*(int *)(*(int *)(iVar1 + local_24 * 4) + 0x4c) + 0x1e),
            iVar4 != -1)))) {
          FUN_800200e8(iVar4,0);
        }
      }
    }
    uVar2 = FUN_8002b9ec();
    FUN_80036e58(0x10,param_1,local_20);
    uVar3 = FUN_8029729c(uVar2);
    if (((uVar3 & 0x4000) == 0) || (local_20[0] <= FLOAT_803e37c4)) {
      (**(code **)(*DAT_803dcac0 + 0x24))(uVar5,1);
    }
    else {
      (**(code **)(*DAT_803dcac0 + 0x24))(uVar5,0);
      FUN_8011f3ec(5);
      *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 1;
    }
    *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) & 0xfffffffd;
  }
  return;
}

