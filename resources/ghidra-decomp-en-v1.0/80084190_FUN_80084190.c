// Function: FUN_80084190
// Entry: 80084190
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x8008439c) */

void FUN_80084190(double param_1,int *param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int unaff_r31;
  undefined4 uVar5;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = 0;
  if (param_1 < (double)(float)param_2[2]) {
    iVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(*param_2);
  }
  if (iVar4 != 0) {
    while (param_1 < (double)(float)param_2[2]) {
      uVar2 = 1;
      for (iVar3 = 0; iVar3 < 4; iVar3 = iVar3 + 1) {
        iVar1 = *(int *)(iVar4 + iVar3 * 4 + 0x1c);
        if ((-1 < iVar1) && (((int)*(char *)(iVar4 + 0x1b) & uVar2) != 0)) {
          iVar3 = 5;
          unaff_r31 = iVar1;
        }
        uVar2 = uVar2 << 1;
      }
      if (iVar3 != 6) {
        param_2[10] = param_2[2];
        param_2[1] = *param_2;
        *param_2 = -1;
        goto LAB_8008439c;
      }
      param_2[1] = *param_2;
      *param_2 = unaff_r31;
      iVar3 = (**(code **)(*DAT_803dca9c + 0x1c))(*param_2);
      FUN_80083e00((double)(float)param_2[2],param_2,iVar3,iVar4,1);
      iVar4 = iVar3;
    }
  }
  iVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(param_2[1]);
  if (iVar4 != 0) {
    while ((double)(float)param_2[10] <= param_1) {
      uVar2 = 1;
      for (iVar3 = 0; iVar3 < 4; iVar3 = iVar3 + 1) {
        iVar1 = *(int *)(iVar4 + iVar3 * 4 + 0x1c);
        if ((-1 < iVar1) && (((int)*(char *)(iVar4 + 0x1b) & uVar2) == 0)) {
          iVar3 = 5;
          unaff_r31 = iVar1;
        }
        uVar2 = uVar2 << 1;
      }
      if (iVar3 != 6) {
        param_2[2] = param_2[10];
        *param_2 = param_2[1];
        param_2[1] = -1;
        break;
      }
      *param_2 = param_2[1];
      param_2[1] = unaff_r31;
      iVar3 = (**(code **)(*DAT_803dca9c + 0x1c))(param_2[1]);
      FUN_80083e00((double)(float)param_2[10],param_2,iVar4,iVar3,0);
      iVar4 = iVar3;
    }
  }
LAB_8008439c:
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

