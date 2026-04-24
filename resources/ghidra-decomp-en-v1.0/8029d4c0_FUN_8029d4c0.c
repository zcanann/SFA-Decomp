// Function: FUN_8029d4c0
// Entry: 8029d4c0
// Size: 816 bytes

/* WARNING: Removing unreachable block (ram,0x8029d7cc) */

undefined4 FUN_8029d4c0(double param_1,int param_2,int param_3)

{
  short sVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar6 = *(int *)(param_2 + 0xb8);
  sVar1 = *(short *)(param_2 + 0xa0);
  if (sVar1 == 199) {
LAB_8029d774:
    FUN_80030334((double)FLOAT_803e7ea4,param_2,0xc4,0);
  }
  else if (sVar1 < 199) {
    if (sVar1 == 0xc5) goto LAB_8029d774;
    if (sVar1 < 0xc5) {
      if (sVar1 < 0xc4) goto LAB_8029d774;
      *(float *)(param_3 + 0x2a0) = FLOAT_803e7f6c;
      if ((*(float *)(param_2 + 0x28) < FLOAT_803e7ee0) && ((*(byte *)(iVar6 + 0x3f1) & 1) != 0)) {
        if (*(short *)(iVar6 + 0x81a) == 0) {
          uVar4 = 0x2d2;
        }
        else {
          uVar4 = 0x214;
        }
        FUN_8000bb18(param_2,uVar4);
        FUN_80030334((double)FLOAT_803e7ea4,param_2,0xc6,0);
      }
      if (FLOAT_803e7ee0 <
          *(float *)(param_2 + 0x24) * *(float *)(param_2 + 0x24) +
          *(float *)(param_2 + 0x2c) * *(float *)(param_2 + 0x2c)) {
        uVar3 = FUN_800217c0();
        iVar5 = (uVar3 & 0xffff) - ((int)*(short *)(iVar6 + 0x478) & 0xffffU);
        if (0x8000 < iVar5) {
          iVar5 = iVar5 + -0xffff;
        }
        if (iVar5 < -0x8000) {
          iVar5 = iVar5 + 0xffff;
        }
        *(short *)(iVar6 + 0x478) = *(short *)(iVar6 + 0x478) + (short)(iVar5 * (int)param_1 >> 3);
        *(undefined2 *)(iVar6 + 0x484) = *(undefined2 *)(iVar6 + 0x478);
      }
    }
    else {
      *(float *)(param_3 + 0x2a0) = FLOAT_803e7f6c;
      if (*(char *)(param_3 + 0x346) != '\0') {
        FUN_80030334((double)FLOAT_803e7ea4,param_2,200,0);
      }
      fVar2 = FLOAT_803e7ea4;
      *(float *)(param_2 + 0x24) = FLOAT_803e7ea4;
      *(float *)(param_2 + 0x2c) = fVar2;
    }
  }
  else if (sVar1 == 0x450) {
    *(float *)(param_3 + 0x2a0) = FLOAT_803e7fcc;
    if ((*(float *)(param_2 + 0x28) < FLOAT_803e7ee0) && ((*(byte *)(iVar6 + 0x3f1) & 1) != 0)) {
      if (*(short *)(iVar6 + 0x81a) == 0) {
        uVar4 = 0x2d2;
      }
      else {
        uVar4 = 0x214;
      }
      FUN_8000bb18(param_2,uVar4);
      FUN_80030334((double)FLOAT_803e7ea4,param_2,0xc6,0);
    }
    if (FLOAT_803e7ee0 <
        *(float *)(param_2 + 0x24) * *(float *)(param_2 + 0x24) +
        *(float *)(param_2 + 0x2c) * *(float *)(param_2 + 0x2c)) {
      uVar3 = FUN_800217c0();
      iVar5 = (uVar3 & 0xffff) - ((int)*(short *)(iVar6 + 0x478) & 0xffffU);
      if (0x8000 < iVar5) {
        iVar5 = iVar5 + -0xffff;
      }
      if (iVar5 < -0x8000) {
        iVar5 = iVar5 + 0xffff;
      }
      *(short *)(iVar6 + 0x478) = *(short *)(iVar6 + 0x478) + (short)(iVar5 * (int)param_1 >> 3);
      *(undefined2 *)(iVar6 + 0x484) = *(undefined2 *)(iVar6 + 0x478);
    }
  }
  else {
    if ((0x44f < sVar1) || (200 < sVar1)) goto LAB_8029d774;
    *(float *)(param_3 + 0x2a0) = FLOAT_803e7ef8;
    if (*(char *)(param_3 + 0x346) != '\0') {
      *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x800000;
      *(code **)(param_3 + 0x308) = FUN_802a514c;
      uVar4 = 0xffffffff;
      goto LAB_8029d7cc;
    }
  }
  *(byte *)(param_3 + 0x34c) = *(byte *)(param_3 + 0x34c) | 2;
  dVar8 = (double)FUN_80292b44((double)FLOAT_803e7fd0,param_1);
  *(float *)(param_2 + 0x24) = (float)((double)*(float *)(param_2 + 0x24) * dVar8);
  dVar8 = (double)FUN_80292b44((double)FLOAT_803e7fd0,param_1);
  *(float *)(param_2 + 0x2c) = (float)((double)*(float *)(param_2 + 0x2c) * dVar8);
  uVar4 = 0;
LAB_8029d7cc:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return uVar4;
}

