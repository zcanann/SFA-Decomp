// Function: FUN_8008441c
// Entry: 8008441c
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x80084628) */
/* WARNING: Removing unreachable block (ram,0x8008442c) */

void FUN_8008441c(double param_1,int *param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int unaff_r31;
  
  iVar4 = 0;
  if (param_1 < (double)(float)param_2[2]) {
    iVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(*param_2);
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
        return;
      }
      param_2[1] = *param_2;
      *param_2 = unaff_r31;
      iVar3 = (**(code **)(*DAT_803dd71c + 0x1c))(*param_2);
      FUN_8008408c(param_2,iVar3,iVar4,'\x01');
      iVar4 = iVar3;
    }
  }
  iVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(param_2[1]);
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
        return;
      }
      *param_2 = param_2[1];
      param_2[1] = unaff_r31;
      iVar3 = (**(code **)(*DAT_803dd71c + 0x1c))(param_2[1]);
      FUN_8008408c(param_2,iVar4,iVar3,'\0');
      iVar4 = iVar3;
    }
  }
  return;
}

