// Function: FUN_80062d60
// Entry: 80062d60
// Size: 292 bytes

/* WARNING: Removing unreachable block (ram,0x80062e5c) */
/* WARNING: Removing unreachable block (ram,0x80062e64) */

int FUN_80062d60(undefined8 param_1,double param_2,undefined8 param_3,double param_4,
                undefined4 param_5,float *param_6,float *param_7)

{
  int iVar1;
  float **ppfVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  float **local_38 [4];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  dVar6 = param_2;
  if (param_4 < param_2) {
    dVar6 = param_4;
    param_4 = param_2;
  }
  iVar1 = FUN_80065e50(param_1,dVar6,param_5,local_38,0,1);
  *param_6 = (float)dVar6;
  *param_7 = 0.0;
  iVar3 = 0;
  ppfVar2 = local_38[0];
  if (0 < iVar1) {
    do {
      if (((*(char *)(*ppfVar2 + 5) != '\x0e') && (dVar5 = (double)**ppfVar2, dVar6 < dVar5)) &&
         (dVar5 < param_4)) {
        *param_7 = local_38[0][iVar3][4];
        *param_6 = *local_38[0][iVar3];
        iVar1 = 1 - ((int)((uint)(byte)((local_38[0][iVar3][2] < FLOAT_803decb0) << 3) << 0x1c) >>
                    0x1f);
        goto LAB_80062e5c;
      }
      ppfVar2 = ppfVar2 + 1;
      iVar3 = iVar3 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  iVar1 = 0;
LAB_80062e5c:
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return iVar1;
}

