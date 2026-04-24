// Function: FUN_8011313c
// Entry: 8011313c
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x80113258) */

void FUN_8011313c(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  double extraout_f1;
  undefined8 in_f31;
  double dVar6;
  undefined8 uVar7;
  undefined4 local_90;
  float local_8c;
  undefined4 local_88;
  undefined auStack132 [124];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar7 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar7 >> 0x20);
  iVar2 = (int)uVar7;
  dVar6 = extraout_f1;
  iVar1 = FUN_8002b9ec();
  uVar4 = 0;
  if (*(char *)(iVar2 + 0x346) != '\0') {
    if ((*(int *)(iVar2 + 0x2d0) == iVar1) && (*(char *)(iVar2 + 0x354) != '\0')) {
      if (((double)*(float *)(iVar2 + 0x2c0) <= dVar6) || (param_3 == 0)) {
        iVar2 = FUN_80295a04(iVar1,1);
        if (iVar2 == 0) {
          uVar4 = 1;
        }
        else {
          iVar2 = FUN_80296ae8(iVar1);
          if (iVar2 < 1) {
            uVar4 = 1;
          }
          else {
            local_90 = *(undefined4 *)(iVar1 + 0xc);
            local_8c = FLOAT_803e1c68 + *(float *)(iVar1 + 0x10);
            local_88 = *(undefined4 *)(iVar1 + 0x14);
            iVar3 = FUN_800640cc((double)FLOAT_803e1c48,iVar3 + 0xc,&local_90,0,auStack132,iVar3,4,
                                 0xffffffff,0,0);
            if (iVar3 != 0) {
              uVar4 = 1;
            }
          }
        }
      }
      else {
        uVar4 = 1;
      }
    }
    else {
      uVar4 = 1;
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  FUN_80286128(uVar4);
  return;
}

