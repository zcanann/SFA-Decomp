// Function: FUN_80232d74
// Entry: 80232d74
// Size: 1084 bytes

void FUN_80232d74(short *param_1,short *param_2)

{
  short sVar1;
  float fVar2;
  undefined2 uVar4;
  char cVar5;
  uint uVar3;
  int iVar6;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  local_28[0] = DAT_803e7160;
  iVar6 = *(int *)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0xc) << 8;
  param_1[1] = (ushort)*(byte *)((int)param_2 + 0x19) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0xd) << 8;
  *(byte *)(iVar6 + 0x160) = *(byte *)(iVar6 + 0x160) & 0xef | 0x10;
  *(undefined *)(iVar6 + 0x15e) = 1;
  uStack28 = (uint)*(byte *)(param_2 + 0x18);
  local_20 = 0x43300000;
  *(float *)(iVar6 + 0x108) =
       (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e7180) * FLOAT_803e716c;
  *(undefined4 *)(iVar6 + 0x10c) = *(undefined4 *)(iVar6 + 0x108);
  *(ushort *)(iVar6 + 0x140) = (ushort)*(byte *)((int)param_2 + 0x1b) << 4;
  *(ushort *)(iVar6 + 0x142) = (ushort)*(byte *)(param_2 + 0xe) << 4;
  *(ushort *)(iVar6 + 0x144) = (ushort)*(byte *)((int)param_2 + 0x1d) << 4;
  FUN_80035960(param_1,4);
  sVar1 = *param_2;
  if ((sVar1 == 0x616) || (sVar1 == 0x617)) {
    *(undefined *)(iVar6 + 0x15c) = 3;
    if (*param_2 == 0x616) {
      *(byte *)(iVar6 + 0x160) = *(byte *)(iVar6 + 0x160) & 0xef;
    }
    if (*param_2 == 0x616) {
      *(float *)(iVar6 + 0x130) = FLOAT_803e71c0;
    }
    else {
      *(float *)(iVar6 + 0x130) = FLOAT_803e71c4;
    }
    *(undefined *)(iVar6 + 0x157) = 5;
    *(undefined *)(iVar6 + 0x158) = 0;
    if (*param_2 == 0x616) {
      *(undefined *)(iVar6 + 0x156) = 2;
    }
    else {
      *(undefined *)(iVar6 + 0x156) = 1;
    }
    uVar4 = FUN_800221a0(0xfffffed4,300);
    *(undefined2 *)(iVar6 + 0x140) = uVar4;
    uVar4 = FUN_800221a0(0xfffffed4,300);
    *(undefined2 *)(iVar6 + 0x142) = uVar4;
    uVar4 = FUN_800221a0(0xfffffed4,300);
    *(undefined2 *)(iVar6 + 0x144) = uVar4;
    *(byte *)(iVar6 + 0x160) = *(byte *)(iVar6 + 0x160) & 0x7f | 0x80;
  }
  else if (sVar1 == 0x7f0) {
    *(undefined *)(iVar6 + 0x15c) = 2;
    *(byte *)(iVar6 + 0x160) = *(byte *)(iVar6 + 0x160) & 0xef;
    *(float *)(iVar6 + 0x130) = FLOAT_803e71c0;
  }
  else {
    *(undefined *)(iVar6 + 0x15c) = 1;
    *(float *)(iVar6 + 0x130) = FLOAT_803e71c4;
    *(undefined *)(iVar6 + 0x156) = 1;
    *(undefined *)(iVar6 + 0x157) = 0x14;
    *(undefined *)(iVar6 + 0x158) = 0;
    *(float *)(iVar6 + 0x11c) = FLOAT_803e71c8;
    fVar2 = FLOAT_803e7170;
    *(float *)(iVar6 + 0x120) = FLOAT_803e7170;
    *(byte *)(iVar6 + 0x160) = *(byte *)(iVar6 + 0x160) & 0x7f | 0x80;
    sVar1 = param_1[0x23];
    if (sVar1 == 0x6d6) {
      *(undefined *)(iVar6 + 0x15a) = 1;
      *(undefined *)(iVar6 + 0x15b) = 2;
      *(float *)(iVar6 + 0x114) = FLOAT_803e71cc;
      *(float *)(iVar6 + 0x118) = FLOAT_803e71d0;
    }
    else {
      if (sVar1 < 0x6d6) {
        if (0x6d4 < sVar1) {
          *(undefined *)(iVar6 + 0x15a) = 0;
          *(undefined *)(iVar6 + 0x15b) = 1;
          goto LAB_80233018;
        }
      }
      else if (sVar1 < 0x6d8) {
        *(undefined *)(iVar6 + 0x15a) = 1;
        *(undefined *)(iVar6 + 0x15b) = 1;
        *(float *)(iVar6 + 0x114) = fVar2;
        *(float *)(iVar6 + 0x118) = FLOAT_803e71d0;
        goto LAB_80233018;
      }
      *(undefined *)(iVar6 + 0x15a) = 1;
      *(undefined *)(iVar6 + 0x15b) = 1;
      *(float *)(iVar6 + 0x114) = FLOAT_803e7170;
      *(float *)(iVar6 + 0x118) = FLOAT_803e71d0;
    }
  }
LAB_80233018:
  uStack28 = (uint)(ushort)param_2[0x12];
  local_20 = 0x43300000;
  *(float *)(iVar6 + 0x134) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e7180);
  if (*(float *)(iVar6 + 0x130) < *(float *)(iVar6 + 0x134)) {
    *(float *)(iVar6 + 0x134) = *(float *)(iVar6 + 0x130);
  }
  *(undefined *)(param_1 + 0x1b) = 0;
  param_1[3] = param_1[3] | 0x4000;
  FUN_8008016c(iVar6 + 300);
  if (*(char *)((int)param_2 + 0x2f) != '\0') {
    if ((*(char *)(iVar6 + 0x15c) == '\x01') || (*(char *)(iVar6 + 0x15c) == '\x02')) {
      local_28[0] = 0x28;
    }
    else {
      local_28[0] = 2;
    }
    cVar5 = (**(code **)(*DAT_803dca9c + 0x8c))
                      ((double)FLOAT_803e71d4,iVar6,param_1,local_28,0xffffffff);
    if (cVar5 == '\0') {
      *(byte *)(iVar6 + 0x160) = *(byte *)(iVar6 + 0x160) & 0xbf | 0x40;
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar6 + 0x68);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar6 + 0x6c);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar6 + 0x70);
      FUN_80231c90(param_1,iVar6);
    }
  }
  uVar4 = FUN_800221a0(0,0xffff);
  *(undefined2 *)(iVar6 + 0x146) = uVar4;
  uVar4 = FUN_800221a0(0,0xffff);
  *(undefined2 *)(iVar6 + 0x148) = uVar4;
  uVar4 = FUN_800221a0(200,300);
  *(undefined2 *)(iVar6 + 0x14a) = uVar4;
  uVar4 = FUN_800221a0(200,300);
  *(undefined2 *)(iVar6 + 0x14c) = uVar4;
  uVar3 = FUN_800221a0(1000,2000);
  *(float *)(iVar6 + 0x138) =
       (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e7178);
  *(undefined *)(iVar6 + 0x15d) = *(undefined *)((int)param_2 + 0x31);
  return;
}

