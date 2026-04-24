// Function: FUN_8005b2fc
// Entry: 8005b2fc
// Size: 404 bytes

/* WARNING: Removing unreachable block (ram,0x8005b46c) */
/* WARNING: Removing unreachable block (ram,0x8005b474) */

int FUN_8005b2fc(double param_1,double param_2,double param_3)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f30;
  undefined8 in_f31;
  double local_30;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  dVar6 = (double)FUN_80291e40((double)(float)(param_1 / (double)FLOAT_803debb4));
  iVar2 = (int)(dVar6 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dcdd0 ^ 0x80000000) -
                                       DOUBLE_803debc0));
  dVar6 = (double)FUN_80291e40((double)(float)(param_3 / (double)FLOAT_803debb4));
  iVar4 = (int)(dVar6 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dcdd4 ^ 0x80000000) -
                                       DOUBLE_803debc0));
  if ((iVar2 < 0) || (0xf < iVar2)) {
    iVar2 = -1;
  }
  else if ((iVar4 < 0) || (0xf < iVar4)) {
    iVar2 = -1;
  }
  else {
    iVar2 = iVar2 + iVar4 * 0x10;
    piVar3 = &DAT_803822b4;
    iVar4 = 5;
    do {
      iVar1 = (int)*(char *)(iVar2 + *piVar3);
      if (-1 < iVar1) {
        iVar1 = *(int *)(DAT_803dce9c + iVar1 * 4);
        local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar1 + 0x8a) - 0x32U ^ 0x80000000);
        if (((double)(float)(local_30 - DOUBLE_803debc0) < param_2) &&
           (local_30 = (double)CONCAT44(0x43300000,
                                        (int)*(short *)(iVar1 + 0x8c) + 0x32U ^ 0x80000000),
           param_2 < (double)(float)(local_30 - DOUBLE_803debc0))) {
          iVar2 = (int)*(char *)(*piVar3 + iVar2);
          goto LAB_8005b46c;
        }
      }
      piVar3 = piVar3 + 1;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    iVar2 = -1;
  }
LAB_8005b46c:
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  return iVar2;
}

