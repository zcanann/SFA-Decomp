// Function: FUN_801ea678
// Entry: 801ea678
// Size: 476 bytes

/* WARNING: Removing unreachable block (ram,0x801ea82c) */
/* WARNING: Removing unreachable block (ram,0x801ea834) */

double FUN_801ea678(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  double in_f30;
  double in_f31;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  if ((DAT_803dc0bc == -1) ||
     (iVar3 = (**(code **)(*DAT_803dca6c + 0x34))(param_2 + 0x28), iVar3 < DAT_803dc0bc)) {
    if (DAT_803dc0bc == -1) {
      iVar3 = FUN_8002b9ec();
      dVar5 = (double)FUN_80021704(param_1 + 0x18,iVar3 + 0x18);
      fVar1 = (float)(dVar5 * (double)FLOAT_803e5af8);
    }
    else {
      in_f31 = (double)(FLOAT_803e5b48 *
                        (float)((double)CONCAT44(0x43300000,DAT_803ad0a4 ^ 0x80000000) -
                               DOUBLE_803e5b00) + FLOAT_803e5b48 * DAT_803ad094);
      in_f30 = (double)(FLOAT_803e5b48 *
                        (float)((double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x44) ^ 0x80000000)
                               - DOUBLE_803e5b00) + FLOAT_803e5b48 * *(float *)(param_2 + 0x34));
      fVar1 = (float)(in_f31 - in_f30);
      if (fVar1 < FLOAT_803e5ae8) {
        fVar1 = -fVar1;
      }
    }
    fVar2 = *(float *)(param_2 + 0x1c);
    if (fVar2 < fVar1) {
      if (fVar1 < *(float *)(param_2 + 0x18)) {
        dVar5 = (double)(((fVar1 - fVar2) / (*(float *)(param_2 + 0x18) - fVar2)) *
                         (*(float *)(param_2 + 0x20) - *(float *)(param_2 + 0x24)) +
                        *(float *)(param_2 + 0x24));
      }
      else {
        dVar5 = (double)*(float *)(param_2 + 0x20);
      }
    }
    else {
      dVar5 = (double)*(float *)(param_2 + 0x24);
    }
    if (*(char *)(param_2 + 0x434) == '\0') {
      fVar1 = (float)(in_f30 - in_f31);
      if (fVar1 < FLOAT_803e5ae8) {
        fVar1 = -fVar1;
      }
      if (FLOAT_803dc0e0 < fVar1) {
        dVar5 = (double)FLOAT_803e5ae8;
      }
    }
  }
  else {
    iVar3 = (**(code **)(*DAT_803dca6c + 0x34))(param_2 + 0x28);
    if (iVar3 == 2) {
      dVar5 = (double)FLOAT_803e5b60;
    }
    else {
      dVar5 = (double)FLOAT_803e5b64;
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return dVar5;
}

