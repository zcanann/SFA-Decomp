// Function: FUN_801a78c8
// Entry: 801a78c8
// Size: 280 bytes

/* WARNING: Removing unreachable block (ram,0x801a79b8) */
/* WARNING: Removing unreachable block (ram,0x801a79c0) */

int FUN_801a78c8(undefined8 param_1,double param_2,undefined8 param_3,double param_4,
                undefined4 param_5,float *param_6,float *param_7)

{
  int iVar1;
  int iVar2;
  float **ppfVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f30;
  undefined8 in_f31;
  float **local_38 [4];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar2 = FUN_80065e50(param_5,local_38,0,1);
  *param_6 = (float)param_2;
  *param_7 = 0.0;
  iVar4 = 0;
  iVar1 = iVar2 + -1;
  ppfVar3 = local_38[0];
  if (0 < iVar2) {
    do {
      if (((*(char *)(*ppfVar3 + 5) != '\x0e') && (dVar6 = (double)**ppfVar3, param_2 < dVar6)) &&
         ((dVar6 < param_4 || (iVar4 == iVar1)))) {
        *param_7 = local_38[0][iVar4][4];
        *param_6 = *local_38[0][iVar4];
        iVar1 = 1 - ((int)((uint)(byte)((local_38[0][iVar4][2] < FLOAT_803e4548) << 3) << 0x1c) >>
                    0x1f);
        goto LAB_801a79b8;
      }
      ppfVar3 = ppfVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  iVar1 = 0;
LAB_801a79b8:
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  return iVar1;
}

