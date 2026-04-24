// Function: FUN_80262fac
// Entry: 80262fac
// Size: 376 bytes

void FUN_80262fac(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  ushort uVar1;
  int *piVar2;
  int iVar3;
  char *pcVar4;
  undefined *puVar5;
  int iVar6;
  int unaff_r30;
  int *local_2c [2];
  
  *param_3 = 0xffffffff;
  iVar3 = FUN_8025edc8(param_1,local_2c);
  piVar2 = local_2c[0];
  if (-1 < iVar3) {
    if (*local_2c[0] == 0) {
      iVar6 = -3;
    }
    else {
      pcVar4 = (char *)FUN_802608b0(local_2c[0]);
      iVar3 = 0;
      do {
        if (*pcVar4 == -1) {
          iVar6 = -4;
        }
        else {
          puVar5 = (undefined *)piVar2[0x43];
          if ((puVar5 == &DAT_803af400) ||
             ((iVar6 = FUN_8028f228(pcVar4,puVar5,4), iVar6 == 0 &&
              (iVar6 = FUN_8028f228(pcVar4 + 4,piVar2[0x43] + 4,2), iVar6 == 0)))) {
            iVar6 = 0;
          }
          else {
            iVar6 = -10;
          }
        }
        if ((-1 < iVar6) && (iVar6 = FUN_80262d2c(pcVar4,param_2), iVar6 != 0)) {
          iVar6 = 0;
          unaff_r30 = iVar3;
          goto LAB_802630b0;
        }
        iVar3 = iVar3 + 1;
        pcVar4 = pcVar4 + 0x40;
      } while (iVar3 < 0x7f);
      iVar6 = -4;
    }
LAB_802630b0:
    if (-1 < iVar6) {
      iVar3 = FUN_802608b0(local_2c[0]);
      iVar3 = iVar3 + unaff_r30 * 0x40;
      uVar1 = *(ushort *)(iVar3 + 0x36);
      if ((uVar1 < 5) || (*(ushort *)(local_2c[0] + 4) <= uVar1)) {
        iVar6 = -6;
      }
      else {
        *param_3 = param_1;
        param_3[1] = unaff_r30;
        param_3[2] = 0;
        *(undefined2 *)(param_3 + 4) = *(undefined2 *)(iVar3 + 0x36);
      }
    }
    FUN_8025ee80(local_2c[0],iVar6);
  }
  return;
}

