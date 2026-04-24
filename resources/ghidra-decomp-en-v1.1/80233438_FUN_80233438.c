// Function: FUN_80233438
// Entry: 80233438
// Size: 1084 bytes

void FUN_80233438(short *param_1,short *param_2)

{
  short sVar1;
  float fVar2;
  uint uVar3;
  char cVar4;
  int iVar5;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  local_28[0] = DAT_803e7df8;
  iVar5 = *(int *)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0xc) << 8;
  param_1[1] = (ushort)*(byte *)((int)param_2 + 0x19) << 8;
  param_1[2] = (ushort)*(byte *)(param_2 + 0xd) << 8;
  *(byte *)(iVar5 + 0x160) = *(byte *)(iVar5 + 0x160) & 0xef | 0x10;
  *(undefined *)(iVar5 + 0x15e) = 1;
  uStack_1c = (uint)*(byte *)(param_2 + 0x18);
  local_20 = 0x43300000;
  *(float *)(iVar5 + 0x108) =
       (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7e18) * FLOAT_803e7e04;
  *(undefined4 *)(iVar5 + 0x10c) = *(undefined4 *)(iVar5 + 0x108);
  *(ushort *)(iVar5 + 0x140) = (ushort)*(byte *)((int)param_2 + 0x1b) << 4;
  *(ushort *)(iVar5 + 0x142) = (ushort)*(byte *)(param_2 + 0xe) << 4;
  *(ushort *)(iVar5 + 0x144) = (ushort)*(byte *)((int)param_2 + 0x1d) << 4;
  FUN_80035a58((int)param_1,4);
  sVar1 = *param_2;
  if ((sVar1 == 0x616) || (sVar1 == 0x617)) {
    *(undefined *)(iVar5 + 0x15c) = 3;
    if (*param_2 == 0x616) {
      *(byte *)(iVar5 + 0x160) = *(byte *)(iVar5 + 0x160) & 0xef;
    }
    if (*param_2 == 0x616) {
      *(float *)(iVar5 + 0x130) = FLOAT_803e7e58;
    }
    else {
      *(float *)(iVar5 + 0x130) = FLOAT_803e7e5c;
    }
    *(undefined *)(iVar5 + 0x157) = 5;
    *(undefined *)(iVar5 + 0x158) = 0;
    if (*param_2 == 0x616) {
      *(undefined *)(iVar5 + 0x156) = 2;
    }
    else {
      *(undefined *)(iVar5 + 0x156) = 1;
    }
    uVar3 = FUN_80022264(0xfffffed4,300);
    *(short *)(iVar5 + 0x140) = (short)uVar3;
    uVar3 = FUN_80022264(0xfffffed4,300);
    *(short *)(iVar5 + 0x142) = (short)uVar3;
    uVar3 = FUN_80022264(0xfffffed4,300);
    *(short *)(iVar5 + 0x144) = (short)uVar3;
    *(byte *)(iVar5 + 0x160) = *(byte *)(iVar5 + 0x160) & 0x7f | 0x80;
  }
  else if (sVar1 == 0x7f0) {
    *(undefined *)(iVar5 + 0x15c) = 2;
    *(byte *)(iVar5 + 0x160) = *(byte *)(iVar5 + 0x160) & 0xef;
    *(float *)(iVar5 + 0x130) = FLOAT_803e7e58;
  }
  else {
    *(undefined *)(iVar5 + 0x15c) = 1;
    *(float *)(iVar5 + 0x130) = FLOAT_803e7e5c;
    *(undefined *)(iVar5 + 0x156) = 1;
    *(undefined *)(iVar5 + 0x157) = 0x14;
    *(undefined *)(iVar5 + 0x158) = 0;
    *(float *)(iVar5 + 0x11c) = FLOAT_803e7e60;
    fVar2 = FLOAT_803e7e08;
    *(float *)(iVar5 + 0x120) = FLOAT_803e7e08;
    *(byte *)(iVar5 + 0x160) = *(byte *)(iVar5 + 0x160) & 0x7f | 0x80;
    sVar1 = param_1[0x23];
    if (sVar1 == 0x6d6) {
      *(undefined *)(iVar5 + 0x15a) = 1;
      *(undefined *)(iVar5 + 0x15b) = 2;
      *(float *)(iVar5 + 0x114) = FLOAT_803e7e64;
      *(float *)(iVar5 + 0x118) = FLOAT_803e7e68;
    }
    else {
      if (sVar1 < 0x6d6) {
        if (0x6d4 < sVar1) {
          *(undefined *)(iVar5 + 0x15a) = 0;
          *(undefined *)(iVar5 + 0x15b) = 1;
          goto LAB_802336dc;
        }
      }
      else if (sVar1 < 0x6d8) {
        *(undefined *)(iVar5 + 0x15a) = 1;
        *(undefined *)(iVar5 + 0x15b) = 1;
        *(float *)(iVar5 + 0x114) = fVar2;
        *(float *)(iVar5 + 0x118) = FLOAT_803e7e68;
        goto LAB_802336dc;
      }
      *(undefined *)(iVar5 + 0x15a) = 1;
      *(undefined *)(iVar5 + 0x15b) = 1;
      *(float *)(iVar5 + 0x114) = FLOAT_803e7e08;
      *(float *)(iVar5 + 0x118) = FLOAT_803e7e68;
    }
  }
LAB_802336dc:
  uStack_1c = (uint)(ushort)param_2[0x12];
  local_20 = 0x43300000;
  *(float *)(iVar5 + 0x134) = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7e18);
  if (*(float *)(iVar5 + 0x130) < *(float *)(iVar5 + 0x134)) {
    *(float *)(iVar5 + 0x134) = *(float *)(iVar5 + 0x130);
  }
  *(undefined *)(param_1 + 0x1b) = 0;
  param_1[3] = param_1[3] | 0x4000;
  FUN_800803f8((undefined4 *)(iVar5 + 300));
  if (*(char *)((int)param_2 + 0x2f) != '\0') {
    if ((*(char *)(iVar5 + 0x15c) == '\x01') || (*(char *)(iVar5 + 0x15c) == '\x02')) {
      local_28[0] = 0x28;
    }
    else {
      local_28[0] = 2;
    }
    cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)FLOAT_803e7e6c,iVar5,param_1,local_28,0xffffffff);
    if (cVar4 == '\0') {
      *(byte *)(iVar5 + 0x160) = *(byte *)(iVar5 + 0x160) & 0xbf | 0x40;
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar5 + 0x68);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar5 + 0x6c);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar5 + 0x70);
      FUN_80232354();
    }
  }
  uVar3 = FUN_80022264(0,0xffff);
  *(short *)(iVar5 + 0x146) = (short)uVar3;
  uVar3 = FUN_80022264(0,0xffff);
  *(short *)(iVar5 + 0x148) = (short)uVar3;
  uVar3 = FUN_80022264(200,300);
  *(short *)(iVar5 + 0x14a) = (short)uVar3;
  uVar3 = FUN_80022264(200,300);
  *(short *)(iVar5 + 0x14c) = (short)uVar3;
  uVar3 = FUN_80022264(1000,2000);
  *(float *)(iVar5 + 0x138) =
       (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e7e10);
  *(undefined *)(iVar5 + 0x15d) = *(undefined *)((int)param_2 + 0x31);
  return;
}

