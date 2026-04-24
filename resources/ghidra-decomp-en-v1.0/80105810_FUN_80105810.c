// Function: FUN_80105810
// Entry: 80105810
// Size: 1644 bytes

void FUN_80105810(short *param_1)

{
  float fVar1;
  int iVar2;
  short sVar4;
  uint uVar3;
  int iVar5;
  double dVar6;
  float local_148;
  float local_144;
  float local_140;
  undefined auStack316 [4];
  float local_138;
  undefined4 local_134;
  float local_130;
  undefined4 local_12c;
  undefined4 local_128;
  float local_124;
  undefined4 local_120;
  undefined auStack284 [112];
  undefined auStack172 [116];
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  iVar5 = *(int *)(param_1 + 0x52);
  if (iVar5 == 0) {
    return;
  }
  if (*(short *)(iVar5 + 0x44) == 1) {
    FUN_8029656c(iVar5,&local_148);
    FLOAT_803dd52c = FLOAT_803db414 * local_148;
    iVar2 = FUN_80296458(iVar5);
    if (iVar2 == 3) {
      *(float *)(DAT_803dd530 + 0x14) = FLOAT_803e1720;
      *(undefined *)(DAT_803dd530 + 0xc2) = 8;
    }
    else {
      if (iVar2 < 3) {
        if (iVar2 == 1) {
          *(float *)(DAT_803dd530 + 0x14) = FLOAT_803e16ac;
          *(undefined *)(DAT_803dd530 + 0xc2) = 0xff;
          goto LAB_80105920;
        }
        if (0 < iVar2) {
          *(float *)(DAT_803dd530 + 0x14) = FLOAT_803e1718;
          *(undefined *)(DAT_803dd530 + 0xc2) = 0xc;
          goto LAB_80105920;
        }
      }
      else if (iVar2 < 5) {
        *(float *)(DAT_803dd530 + 0x14) = FLOAT_803e171c;
        *(undefined *)(DAT_803dd530 + 0xc2) = 2;
        goto LAB_80105920;
      }
      *(undefined4 *)(DAT_803dd530 + 0x14) = *(undefined4 *)(DAT_803dd530 + 0x58);
      *(undefined *)(DAT_803dd530 + 0xc2) = 8;
    }
  }
  else {
    FLOAT_803dd52c = FLOAT_803db414;
  }
LAB_80105920:
  *(undefined *)(param_1 + 0x9f) = 0;
  FUN_80104540(param_1);
  FUN_80104040(param_1,iVar5);
  FUN_8010509c(param_1,iVar5);
  FUN_8000e0a0((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
               (double)*(float *)(param_1 + 10),param_1 + 0xc,param_1 + 0xe,param_1 + 0x10,
               *(undefined4 *)(param_1 + 0x18));
  FUN_801049b0((double)*(float *)(DAT_803dd530 + 0xa0),(double)*(float *)(DAT_803dd530 + 0xa4),
               param_1,iVar5);
  FUN_801046f4(param_1,1,8,DAT_803dd530 + 0xa0,DAT_803dd530 + 0xa4);
  fVar1 = FLOAT_803e16ac;
  if (*(char *)(DAT_803dd530 + 0xc6) < '\0') {
    *(float *)(param_1 + 0x98) = FLOAT_803e16ac;
    *(float *)(param_1 + 0x96) = fVar1;
    if ((*(char *)(param_1 + 0x51) == '\x01') && (*(float *)(param_1 + 0x1c) < fVar1)) {
      *(byte *)(DAT_803dd530 + 0xc6) = *(byte *)(DAT_803dd530 + 0xc6) & 0x7f;
    }
    if ((FLOAT_803e172c + *(float *)(iVar5 + 0x1c) < *(float *)(param_1 + 0xe)) ||
       (*(float *)(param_1 + 0xe) < FLOAT_803e1708 + *(float *)(iVar5 + 0x1c))) {
      *(byte *)(DAT_803dd530 + 0xc6) = *(byte *)(DAT_803dd530 + 0xc6) & 0x7f;
    }
  }
  else {
    *(undefined *)(DAT_803dd530 + 0xc5) = *(undefined *)(param_1 + 0x51);
    if (((*(char *)(param_1 + 0xa1) != '\0') ||
        ((*(char *)(DAT_803dd530 + 0xc5) == '\x01' && (FLOAT_803e16ac <= *(float *)(param_1 + 0x1c))
         ))) && (-1 < *(char *)(DAT_803dd530 + 200))) {
      if (((FLOAT_803e16dc + *(float *)(iVar5 + 0x1c) < *(float *)(param_1 + 0xe)) &&
          (*(float *)(param_1 + 0xe) < FLOAT_803e1724 + *(float *)(iVar5 + 0x1c))) &&
         (*(int *)(param_1 + 0x18) == 0)) {
        *(byte *)(DAT_803dd530 + 0xc6) = *(byte *)(DAT_803dd530 + 0xc6) & 0x7f | 0x80;
      }
    }
    if ((((*(byte *)(DAT_803dd530 + 0xc5) & 0x10) != 0) &&
        (*(float *)(param_1 + 0x1c) < FLOAT_803e1728)) &&
       (*(float *)(iVar5 + 0x28) <= FLOAT_803e16ac)) {
      *(byte *)(DAT_803dd530 + 200) = *(byte *)(DAT_803dd530 + 200) & 0xbf | 0x40;
      *(undefined4 *)(DAT_803dd530 + 0xbc) = *(undefined4 *)(param_1 + 0xe);
    }
  }
  if (*(char *)(DAT_803dd530 + 200) < '\0') {
    if ((*(char *)(DAT_803dd530 + 0xc5) == '\x01') || (*(char *)(param_1 + 0xa1) != '\0')) {
      *(char *)(DAT_803dd530 + 199) = *(char *)(DAT_803dd530 + 199) + '\x01';
    }
    else {
      *(undefined *)(DAT_803dd530 + 199) = 0;
    }
    if (10 < *(byte *)(DAT_803dd530 + 199)) {
      if (*(short *)(iVar5 + 0x44) == 1) {
        FUN_80296bd4(iVar5,&local_128,&local_124,&local_120);
      }
      else {
        local_128 = *(undefined4 *)(iVar5 + 0x18);
        local_124 = *(float *)(iVar5 + 0x1c) + *(float *)(DAT_803dd530 + 0x8c);
        local_120 = *(undefined4 *)(iVar5 + 0x20);
      }
      FUN_80103524((double)FLOAT_803e1688,&local_128,param_1 + 0xc,param_1 + 0xc,auStack172,3,1,1);
      *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
      *(undefined *)(DAT_803dd530 + 199) = 0;
    }
  }
  if (-1 < *(char *)(DAT_803dd530 + 0xc6)) {
    if ((*(byte *)(DAT_803dd530 + 0xc5) & 0x10) == 0) {
      *(undefined *)(DAT_803dd530 + 0xc3) = 0;
    }
    else {
      *(char *)(DAT_803dd530 + 0xc3) = *(char *)(DAT_803dd530 + 0xc3) + '\x01';
    }
    if (5 < *(byte *)(DAT_803dd530 + 0xc3)) {
      if (*(short *)(iVar5 + 0x44) == 1) {
        FUN_80296bd4(iVar5,&local_134,&local_130,&local_12c);
      }
      else {
        local_134 = *(undefined4 *)(iVar5 + 0x18);
        local_130 = *(float *)(iVar5 + 0x1c) + *(float *)(DAT_803dd530 + 0x8c);
        local_12c = *(undefined4 *)(iVar5 + 0x20);
      }
      FUN_80103524((double)FLOAT_803e1688,&local_134,param_1 + 0xc,param_1 + 0xc,auStack284,3,1,1);
      *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
      *(undefined *)(DAT_803dd530 + 0xc3) = 0;
    }
  }
  (**(code **)(*DAT_803dca50 + 0x38))
            ((double)*(float *)(DAT_803dd530 + 0x8c),param_1,&local_138,auStack316,&local_140,
             &local_144,0);
  sVar4 = FUN_800217c0((double)local_138,(double)local_140);
  *(undefined2 *)(DAT_803dd530 + 0x80) = 0;
  *param_1 = (-0x8000 - sVar4) - *(short *)(DAT_803dd530 + 0x80);
  uVar3 = FUN_800217c0((double)(*(float *)(param_1 + 0xe) -
                               (*(float *)(iVar5 + 0x1c) + *(float *)(DAT_803dd530 + 0x8c))),
                       (double)local_144);
  uStack52 = (uVar3 & 0xffff) - ((int)param_1[1] & 0xffffU);
  if (0x8000 < (int)uStack52) {
    uStack52 = uStack52 - 0xffff;
  }
  if ((int)uStack52 < -0x8000) {
    uStack52 = uStack52 + 0xffff;
  }
  uStack52 = uStack52 ^ 0x80000000;
  local_38 = 0x43300000;
  uStack44 = (uint)*(byte *)(DAT_803dd530 + 0xc2);
  local_30 = 0x43300000;
  dVar6 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,uStack52) -
                                              DOUBLE_803e1698),
                               (double)(FLOAT_803e16a4 /
                                       (float)((double)CONCAT44(0x43300000,uStack44) -
                                              DOUBLE_803e16f8)),(double)FLOAT_803db414);
  local_28 = (longlong)(int)dVar6;
  param_1[1] = param_1[1] + (short)(int)dVar6;
  FUN_80103950(param_1,iVar5);
  uStack28 = (int)param_1[2] ^ 0x80000000;
  local_20 = 0x43300000;
  dVar6 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,uStack28) -
                                              DOUBLE_803e1698),(double)FLOAT_803e1730,
                               (double)FLOAT_803db414);
  local_18 = (longlong)(int)dVar6;
  param_1[2] = param_1[2] - (short)(int)dVar6;
  FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
               *(undefined4 *)(param_1 + 0x18));
  return;
}

