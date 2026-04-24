// Function: FUN_8017510c
// Entry: 8017510c
// Size: 796 bytes

/* WARNING: Removing unreachable block (ram,0x801753f8) */
/* WARNING: Removing unreachable block (ram,0x80175400) */

undefined4 FUN_8017510c(short *param_1,short *param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar3 + 0x145) = 0x3c;
  if (param_1[0x5a] != -1) {
    (**(code **)(*DAT_803dca50 + 0x4c))();
  }
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  if (*(char *)(param_3 + 0x56) != '\0') {
    if (*(char *)(param_3 + 0x56) != '\x02') {
      *(float *)(param_3 + 0x4c) = FLOAT_803e3588;
      *(float *)(param_3 + 0x40) = *(float *)(param_1 + 6) - *(float *)(param_2 + 6);
      *(float *)(param_3 + 0x44) = *(float *)(param_1 + 8) - *(float *)(param_2 + 8);
      *(float *)(param_3 + 0x48) = *(float *)(param_1 + 10) - *(float *)(param_2 + 10);
      *(short *)(param_3 + 0x50) = *param_1 - *param_2;
      if (0x8000 < *(short *)(param_3 + 0x50)) {
        *(short *)(param_3 + 0x50) = *(short *)(param_3 + 0x50) + 1;
      }
      if (*(short *)(param_3 + 0x50) < -0x8000) {
        *(short *)(param_3 + 0x50) = *(short *)(param_3 + 0x50) + -1;
      }
      *(short *)(param_3 + 0x52) = param_1[1] - param_2[1];
      if (0x8000 < *(short *)(param_3 + 0x52)) {
        *(short *)(param_3 + 0x52) = *(short *)(param_3 + 0x52) + 1;
      }
      if (*(short *)(param_3 + 0x52) < -0x8000) {
        *(short *)(param_3 + 0x52) = *(short *)(param_3 + 0x52) + -1;
      }
      *(short *)(param_3 + 0x54) = param_2[2] - param_1[2];
      if (0x8000 < *(short *)(param_3 + 0x54)) {
        *(short *)(param_3 + 0x54) = *(short *)(param_3 + 0x54) + 1;
      }
      if (*(short *)(param_3 + 0x54) < -0x8000) {
        *(short *)(param_3 + 0x54) = *(short *)(param_3 + 0x54) + -1;
      }
      *(undefined *)(param_3 + 0x56) = 2;
    }
    *(float *)(param_3 + 0x4c) =
         -(*(float *)(param_3 + 0x24) * FLOAT_803db414 - *(float *)(param_3 + 0x4c));
    if (*(float *)(param_3 + 0x4c) <= FLOAT_803e3528) {
      *(undefined *)(param_3 + 0x56) = 0;
    }
  }
  if (*(int *)(param_1 + 0x7c) == 0) {
    *(undefined4 *)(param_1 + 0x7c) = 2;
  }
  if ((param_1[0x23] == 0x21e) || (param_1[0x23] == 0x411)) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    if (('\0' < *(char *)(*(int *)(param_1 + 0x2c) + 0x10f)) &&
       ((*(short *)(*(int *)(*(int *)(param_1 + 0x2c) + 0x100) + 0x44) == 0x24 &&
        (iVar1 = FUN_8001ffb4(0x103), iVar1 == 0)))) {
      FUN_800200e8(0x103,1);
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
      iVar1 = FUN_8002b9ec();
      dVar7 = (double)(*(float *)(param_1 + 6) - *(float *)(iVar1 + 0xc));
      dVar6 = (double)(*(float *)(param_1 + 10) - *(float *)(iVar1 + 0x14));
      dVar5 = (double)FUN_802931a0((double)(float)(dVar7 * dVar7 + (double)(float)(dVar6 * dVar6)));
      if (dVar5 != (double)FLOAT_803e3528) {
        dVar7 = (double)(float)(dVar7 / dVar5);
        dVar6 = (double)(float)(dVar6 / dVar5);
      }
      dVar5 = (double)FLOAT_803e3598;
      *(float *)(iVar3 + 0xc0) = (float)(dVar5 * dVar7);
      *(float *)(iVar3 + 0xc4) = FLOAT_803e3528;
      *(float *)(iVar3 + 200) = (float)(dVar5 * dVar6);
      uVar2 = 4;
      goto LAB_801753f8;
    }
  }
  uVar2 = 0;
LAB_801753f8:
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return uVar2;
}

