// Function: FUN_80161264
// Entry: 80161264
// Size: 516 bytes

/* WARNING: Removing unreachable block (ram,0x80161440) */
/* WARNING: Removing unreachable block (ram,0x80161448) */

undefined4 FUN_80161264(short *param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  short sVar3;
  int iVar4;
  undefined4 uVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar4 = *(int *)(param_2 + 0x2d0);
  if (iVar4 == 0) {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0);
    uVar2 = 1;
  }
  else {
    if (*(short *)(param_2 + 0x274) != 6) {
      dVar7 = (double)(*(float *)(param_1 + 6) - *(float *)(iVar4 + 0xc));
      dVar6 = (double)(*(float *)(param_1 + 10) - *(float *)(iVar4 + 0x14));
      sVar3 = FUN_800217c0(dVar7,dVar6);
      if (((ushort)(sVar3 - *param_1) < 0x4001) ||
         (fVar1 = FLOAT_803e2eb0, 0xbfff < (ushort)(sVar3 - *param_1))) {
        dVar6 = (double)FUN_802931a0((double)(float)(dVar7 * dVar7 + (double)(float)(dVar6 * dVar6))
                                    );
        fVar1 = (float)(dVar6 - (double)FLOAT_803e2eb4);
      }
      dVar7 = (double)fVar1;
      dVar6 = dVar7;
      if (dVar7 < (double)FLOAT_803e2eb8) {
        dVar6 = -dVar7;
      }
      if (((double)FLOAT_803e2ebc <= dVar6) ||
         ((*(short *)(param_2 + 0x274) != 1 &&
          ((*(short *)(param_2 + 0x274) != 5 || (*(char *)(param_2 + 0x346) == '\0')))))) {
        sVar3 = *(short *)(param_2 + 0x274);
        if (sVar3 != 1) {
          if ((((double)FLOAT_803e2ec0 < dVar7) && (sVar3 != 4)) &&
             ((sVar3 != 5 || (*(char *)(param_2 + 0x346) != '\0')))) {
            (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
          }
          if (dVar7 < (double)FLOAT_803e2ec4) {
            (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
          }
        }
      }
      else {
        (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,6);
      }
      if (*(short *)(param_2 + 0x274) == 1) {
        fVar1 = FLOAT_803e2ecc;
        if ((double)FLOAT_803e2eb8 < dVar7) {
          fVar1 = FLOAT_803e2ec8;
        }
        *(float *)(param_2 + 0x2a0) = fVar1;
      }
    }
    uVar2 = 0;
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  return uVar2;
}

