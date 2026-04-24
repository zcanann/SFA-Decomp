// Function: FUN_80108ec8
// Entry: 80108ec8
// Size: 1452 bytes

/* WARNING: Removing unreachable block (ram,0x80108f28) */

void FUN_80108ec8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  byte bVar2;
  float fVar3;
  float fVar4;
  ushort uVar5;
  undefined uVar8;
  uint uVar6;
  int iVar7;
  int iVar9;
  int iVar10;
  int iVar11;
  double dVar12;
  int local_38;
  int local_34;
  float local_30;
  undefined auStack_2c [4];
  float local_28;
  undefined auStack_24 [4];
  longlong local_20;
  undefined8 local_18;
  
  iVar9 = *(int *)(param_9 + 0x52);
  FUN_80014e9c(0);
  FUN_801082ac(iVar9,0);
  bVar2 = *(byte *)(DAT_803de1c0 + 300);
  if (bVar2 == 3) {
    dVar12 = (double)FLOAT_803e24a0;
    iVar10 = FUN_80010340(dVar12,(float *)(DAT_803de1c0 + 0x78));
    local_20 = (longlong)(int)*(float *)(DAT_803de1c0 + 0xe0);
    *param_9 = (short)(int)*(float *)(DAT_803de1c0 + 0xe0);
    iVar9 = DAT_803de1c0;
    local_18 = (double)(longlong)(int)*(float *)(DAT_803de1c0 + 0xe4);
    param_9[1] = (short)(int)*(float *)(DAT_803de1c0 + 0xe4);
    if (iVar10 != 0) {
      *(int *)(DAT_803de1c0 + 0xfc) = DAT_803de1c0 + 0x10;
      *(int *)(DAT_803de1c0 + 0x100) = DAT_803de1c0 + 0x20;
      *(int *)(DAT_803de1c0 + 0x104) = DAT_803de1c0 + 0x30;
      *(undefined4 *)(DAT_803de1c0 + 0x108) = 4;
      *(undefined4 *)(DAT_803de1c0 + 0xf8) = 0;
      *(code **)(DAT_803de1c0 + 0x10c) = FUN_80010de0;
      *(undefined **)(DAT_803de1c0 + 0x110) = &LAB_80010d74;
      FUN_80010a8c(dVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (float *)(DAT_803de1c0 + 0x78),iVar9,param_11,param_12,param_13,param_14,param_15
                   ,param_16);
      *(ushort *)(*(int *)(param_9 + 0x52) + 6) = *(ushort *)(*(int *)(param_9 + 0x52) + 6) & 0xbfff
      ;
      FUN_80101b44(0xf,0xfe);
      *(undefined *)(DAT_803de1c0 + 300) = 4;
      if ((*(byte *)(DAT_803de1c0 + 0x12d) >> 6 & 1) != 0) {
        if ((char)*(byte *)(DAT_803de1c0 + 0x12d) < '\0') {
          uVar5 = 0x3f5;
        }
        else {
          uVar5 = 0x3f3;
        }
        FUN_8000bb38(0,uVar5);
      }
    }
    *(undefined *)(param_9 + 0x9f) = 1;
  }
  else if (bVar2 < 3) {
    if (bVar2 == 1) {
      iVar9 = FUN_80010340((double)FLOAT_803e24a0,(float *)(DAT_803de1c0 + 0x78));
      if (iVar9 != 0) {
        if (*(char *)(DAT_803de1c0 + 0x12d) < '\0') {
          FUN_80055220(1);
        }
        *(undefined *)(DAT_803de1c0 + 300) = 2;
      }
      local_20 = (longlong)(int)*(float *)(DAT_803de1c0 + 0xe0);
      *param_9 = (short)(int)*(float *)(DAT_803de1c0 + 0xe0);
      *(undefined *)(param_9 + 0x9f) = 1;
    }
    else if (bVar2 == 0) {
      uVar8 = FUN_80108b18();
      *(undefined *)(DAT_803de1c0 + 300) = uVar8;
    }
    else {
      if (*(char *)(DAT_803de1c0 + 0x12d) < '\0') {
        FUN_80055220(1);
      }
      FUN_80108718(param_9);
      uVar6 = FUN_80014e9c(0);
      if ((uVar6 & 0x210) != 0) {
        FUN_80014b68(0,0x200);
        FUN_80108430(param_9);
        FUN_80055220(0);
        *(undefined *)(DAT_803de1c0 + 300) = 3;
      }
      *(undefined *)(param_9 + 0x9f) = 0;
    }
  }
  else if ((bVar2 != 5) && (bVar2 < 5)) {
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(DAT_803de1c0 + 0x14);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(DAT_803de1c0 + 0x24);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(DAT_803de1c0 + 0x34);
    fVar3 = (FLOAT_803e2468 - *(float *)(param_9 + 0x7a)) - FLOAT_803e24a4;
    if (fVar3 < FLOAT_803e2444) {
      fVar3 = FLOAT_803e2444;
    }
    fVar4 = fVar3 * FLOAT_803e24a8;
    if (FLOAT_803e2468 < fVar3 * FLOAT_803e24a8) {
      fVar4 = FLOAT_803e2468;
    }
    iVar10 = (int)(FLOAT_803e2494 * fVar4);
    local_18 = (double)(longlong)iVar10;
    iVar11 = *(int *)(param_9 + 0x52);
    if (iVar10 < 1) {
      iVar10 = 1;
    }
    if (iVar11 != 0) {
      *(char *)(iVar11 + 0x36) = (char)iVar10;
      iVar7 = FUN_8002bac4();
      if (((iVar7 == iVar11) && (FUN_80296e34(iVar11,&local_34), local_34 != 0)) &&
         (*(char *)(local_34 + 0x36) = (char)iVar10, *(char *)(local_34 + 0x36) == '\x01')) {
        *(undefined *)(local_34 + 0x36) = 0;
      }
    }
    bVar1 = *(float *)(param_9 + 0x7a) <= FLOAT_803e2444;
    (**(code **)(*DAT_803dd6d0 + 0x38))
              ((double)FLOAT_803e2444,param_9,auStack_24,&local_28,auStack_2c,&local_30,0);
    if (FLOAT_803e24ac <= local_30) {
      local_28 = *(float *)(param_9 + 0xe) - (*(float *)(iVar9 + 0x1c) + FLOAT_803e2440);
      uVar6 = FUN_80021884();
      uVar6 = (uVar6 & 0xffff) - (uint)(ushort)param_9[1];
      if (0x8000 < (int)uVar6) {
        uVar6 = uVar6 - 0xffff;
      }
      if ((int)uVar6 < -0x8000) {
        uVar6 = uVar6 + 0xffff;
      }
      local_18 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      uVar6 = (uint)((float)(local_18 - DOUBLE_803e2458) * FLOAT_803dc074);
      local_20 = (longlong)(int)uVar6;
      param_9[1] = param_9[1] +
                   (short)((int)uVar6 >> 3) + (ushort)((int)uVar6 < 0 && (uVar6 & 7) != 0);
    }
    else {
      param_9[1] = 0;
    }
    if (bVar1) {
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
      iVar9 = *(int *)(param_9 + 0x52);
      if (iVar9 != 0) {
        *(undefined *)(iVar9 + 0x36) = 0xff;
        iVar10 = FUN_8002bac4();
        if (((iVar10 == iVar9) && (FUN_80296e34(iVar9,&local_38), local_38 != 0)) &&
           (*(undefined *)(local_38 + 0x36) = 0xff, *(char *)(local_38 + 0x36) == '\x01')) {
          *(undefined *)(local_38 + 0x36) = 0;
        }
      }
    }
    *(undefined *)(param_9 + 0x9f) = 1;
  }
  iVar9 = FUN_80036974(*(int *)(param_9 + 0x52),(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar9 != 0) {
    FUN_80108430(param_9);
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(DAT_803de1c0 + 0x14);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(DAT_803de1c0 + 0x24);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(DAT_803de1c0 + 0x34);
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0);
  }
  FUN_80137cd0();
  FUN_8000e054((double)*(float *)(param_9 + 0xc),(double)*(float *)(param_9 + 0xe),
               (double)*(float *)(param_9 + 0x10),(float *)(param_9 + 6),(float *)(param_9 + 8),
               (float *)(param_9 + 10),*(int *)(param_9 + 0x18));
  return;
}

