// Function: FUN_800e6a90
// Entry: 800e6a90
// Size: 168 bytes

/* WARNING: Removing unreachable block (ram,0x800e6b18) */
/* WARNING: Removing unreachable block (ram,0x800e6b20) */

double FUN_800e6a90(undefined8 param_1,double param_2,undefined8 param_3,double param_4,
                   undefined4 param_5)

{
  float *pfVar1;
  float *pfVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 in_f30;
  undefined8 in_f31;
  int local_28 [4];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  pfVar1 = (float *)FUN_800e6b38(param_1,param_3,param_5,local_28,1);
  iVar3 = 0;
  pfVar2 = pfVar1;
  if (0 < local_28[0]) {
    do {
      if ((*pfVar2 < (float)(param_2 + param_4)) && (FLOAT_803e0668 < pfVar2[2])) {
        param_2 = (double)pfVar1[iVar3 * 6];
        break;
      }
      pfVar2 = pfVar2 + 6;
      iVar3 = iVar3 + 1;
      local_28[0] = local_28[0] + -1;
    } while (local_28[0] != 0);
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return param_2;
}

