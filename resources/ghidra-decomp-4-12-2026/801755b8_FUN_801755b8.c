// Function: FUN_801755b8
// Entry: 801755b8
// Size: 796 bytes

/* WARNING: Removing unreachable block (ram,0x801758ac) */
/* WARNING: Removing unreachable block (ram,0x801758a4) */
/* WARNING: Removing unreachable block (ram,0x801755d0) */
/* WARNING: Removing unreachable block (ram,0x801755c8) */

undefined4 FUN_801755b8(short *param_1,short *param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar3 + 0x145) = 0x3c;
  if (param_1[0x5a] != -1) {
    (**(code **)(*DAT_803dd6d0 + 0x4c))();
  }
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  if (*(char *)(param_3 + 0x56) != '\0') {
    if (*(char *)(param_3 + 0x56) != '\x02') {
      *(float *)(param_3 + 0x4c) = FLOAT_803e4220;
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
         -(*(float *)(param_3 + 0x24) * FLOAT_803dc074 - *(float *)(param_3 + 0x4c));
    if (*(float *)(param_3 + 0x4c) <= FLOAT_803e41c0) {
      *(undefined *)(param_3 + 0x56) = 0;
    }
  }
  if (*(int *)(param_1 + 0x7c) == 0) {
    param_1[0x7c] = 0;
    param_1[0x7d] = 2;
  }
  if ((param_1[0x23] == 0x21e) || (param_1[0x23] == 0x411)) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    if (('\0' < *(char *)(*(int *)(param_1 + 0x2c) + 0x10f)) &&
       ((*(short *)(*(int *)(*(int *)(param_1 + 0x2c) + 0x100) + 0x44) == 0x24 &&
        (uVar1 = FUN_80020078(0x103), uVar1 == 0)))) {
      FUN_800201ac(0x103,1);
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
      iVar2 = FUN_8002bac4();
      dVar6 = (double)(*(float *)(param_1 + 6) - *(float *)(iVar2 + 0xc));
      dVar5 = (double)(*(float *)(param_1 + 10) - *(float *)(iVar2 + 0x14));
      dVar4 = FUN_80293900((double)(float)(dVar6 * dVar6 + (double)(float)(dVar5 * dVar5)));
      if (dVar4 != (double)FLOAT_803e41c0) {
        dVar6 = (double)(float)(dVar6 / dVar4);
        dVar5 = (double)(float)(dVar5 / dVar4);
      }
      dVar4 = (double)FLOAT_803e4230;
      *(float *)(iVar3 + 0xc0) = (float)(dVar4 * dVar6);
      *(float *)(iVar3 + 0xc4) = FLOAT_803e41c0;
      *(float *)(iVar3 + 200) = (float)(dVar4 * dVar5);
      return 4;
    }
  }
  return 0;
}

