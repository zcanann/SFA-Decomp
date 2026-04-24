// Function: FUN_80263710
// Entry: 80263710
// Size: 376 bytes

void FUN_80263710(int param_1,char *param_2,int *param_3)

{
  ushort uVar1;
  int *piVar2;
  int iVar3;
  char *pcVar4;
  undefined *puVar5;
  int iVar6;
  int unaff_r30;
  int *local_2c [2];
  
  *param_3 = -1;
  iVar3 = FUN_8025f52c(param_1,local_2c);
  piVar2 = local_2c[0];
  if (-1 < iVar3) {
    if (*local_2c[0] == 0) {
      iVar6 = -3;
    }
    else {
      pcVar4 = (char *)FUN_80261014((int)local_2c[0]);
      iVar3 = 0;
      do {
        if (*pcVar4 == -1) {
          iVar6 = -4;
        }
        else {
          puVar5 = (undefined *)piVar2[0x43];
          if ((puVar5 == &DAT_803b0060) ||
             ((iVar6 = FUN_8028f988((int)pcVar4,(int)puVar5,4), iVar6 == 0 &&
              (iVar6 = FUN_8028f988((int)(pcVar4 + 4),piVar2[0x43] + 4,2), iVar6 == 0)))) {
            iVar6 = 0;
          }
          else {
            iVar6 = -10;
          }
        }
        if ((-1 < iVar6) && (iVar6 = FUN_80263490((int)pcVar4,param_2), iVar6 != 0)) {
          iVar6 = 0;
          unaff_r30 = iVar3;
          goto LAB_80263814;
        }
        iVar3 = iVar3 + 1;
        pcVar4 = pcVar4 + 0x40;
      } while (iVar3 < 0x7f);
      iVar6 = -4;
    }
LAB_80263814:
    if (-1 < iVar6) {
      iVar3 = FUN_80261014((int)local_2c[0]);
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
    FUN_8025f5e4(local_2c[0],iVar6);
  }
  return;
}

