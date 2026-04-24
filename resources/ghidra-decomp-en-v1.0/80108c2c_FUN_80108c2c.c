// Function: FUN_80108c2c
// Entry: 80108c2c
// Size: 1452 bytes

/* WARNING: Removing unreachable block (ram,0x80108c8c) */

void FUN_80108c2c(undefined2 *param_1)

{
  bool bVar1;
  byte bVar2;
  float fVar3;
  float fVar4;
  undefined4 uVar5;
  undefined uVar8;
  uint uVar6;
  int iVar7;
  int iVar9;
  int iVar10;
  int iVar11;
  int local_38;
  int local_34;
  float local_30;
  undefined auStack44 [4];
  float local_28;
  undefined auStack36 [4];
  longlong local_20;
  double local_18;
  
  iVar9 = *(int *)(param_1 + 0x52);
  FUN_80014e70(0);
  FUN_80108010(iVar9,0);
  bVar2 = *(byte *)(DAT_803dd548 + 300);
  if (bVar2 == 3) {
    iVar9 = FUN_80010320((double)FLOAT_803e1820,DAT_803dd548 + 0x78);
    local_20 = (longlong)(int)*(float *)(DAT_803dd548 + 0xe0);
    *param_1 = (short)(int)*(float *)(DAT_803dd548 + 0xe0);
    local_18 = (double)(longlong)(int)*(float *)(DAT_803dd548 + 0xe4);
    param_1[1] = (short)(int)*(float *)(DAT_803dd548 + 0xe4);
    if (iVar9 != 0) {
      *(int *)(DAT_803dd548 + 0xfc) = DAT_803dd548 + 0x10;
      *(int *)(DAT_803dd548 + 0x100) = DAT_803dd548 + 0x20;
      *(int *)(DAT_803dd548 + 0x104) = DAT_803dd548 + 0x30;
      *(undefined4 *)(DAT_803dd548 + 0x108) = 4;
      *(undefined4 *)(DAT_803dd548 + 0xf8) = 0;
      *(code **)(DAT_803dd548 + 0x10c) = FUN_80010dc0;
      *(undefined **)(DAT_803dd548 + 0x110) = &LAB_80010d54;
      FUN_80010a6c(DAT_803dd548 + 0x78);
      *(ushort *)(*(int *)(param_1 + 0x52) + 6) = *(ushort *)(*(int *)(param_1 + 0x52) + 6) & 0xbfff
      ;
      FUN_801018a8(0xf,0xfe);
      *(undefined *)(DAT_803dd548 + 300) = 4;
      if ((*(byte *)(DAT_803dd548 + 0x12d) >> 6 & 1) != 0) {
        if ((char)*(byte *)(DAT_803dd548 + 0x12d) < '\0') {
          uVar5 = 0x3f5;
        }
        else {
          uVar5 = 0x3f3;
        }
        FUN_8000bb18(0,uVar5);
      }
    }
    *(undefined *)(param_1 + 0x9f) = 1;
  }
  else if (bVar2 < 3) {
    if (bVar2 == 1) {
      iVar9 = FUN_80010320((double)FLOAT_803e1820,DAT_803dd548 + 0x78);
      if (iVar9 != 0) {
        if (*(char *)(DAT_803dd548 + 0x12d) < '\0') {
          FUN_800550a4(1);
        }
        *(undefined *)(DAT_803dd548 + 300) = 2;
      }
      local_20 = (longlong)(int)*(float *)(DAT_803dd548 + 0xe0);
      *param_1 = (short)(int)*(float *)(DAT_803dd548 + 0xe0);
      *(undefined *)(param_1 + 0x9f) = 1;
    }
    else if (bVar2 == 0) {
      uVar8 = FUN_8010887c(param_1,*(undefined4 *)(param_1 + 0x52));
      *(undefined *)(DAT_803dd548 + 300) = uVar8;
    }
    else {
      if (*(char *)(DAT_803dd548 + 0x12d) < '\0') {
        FUN_800550a4(1);
      }
      FUN_8010847c(param_1);
      uVar6 = FUN_80014e70(0);
      if ((uVar6 & 0x210) != 0) {
        FUN_80014b3c(0,0x200);
        FUN_80108194(param_1);
        FUN_800550a4(0);
        *(undefined *)(DAT_803dd548 + 300) = 3;
      }
      *(undefined *)(param_1 + 0x9f) = 0;
    }
  }
  else if ((bVar2 != 5) && (bVar2 < 5)) {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(DAT_803dd548 + 0x14);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(DAT_803dd548 + 0x24);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(DAT_803dd548 + 0x34);
    fVar3 = (FLOAT_803e17e8 - *(float *)(param_1 + 0x7a)) - FLOAT_803e1824;
    if (fVar3 < FLOAT_803e17c4) {
      fVar3 = FLOAT_803e17c4;
    }
    fVar4 = fVar3 * FLOAT_803e1828;
    if (FLOAT_803e17e8 < fVar3 * FLOAT_803e1828) {
      fVar4 = FLOAT_803e17e8;
    }
    iVar10 = (int)(FLOAT_803e1814 * fVar4);
    local_18 = (double)(longlong)iVar10;
    iVar11 = *(int *)(param_1 + 0x52);
    if (iVar10 < 1) {
      iVar10 = 1;
    }
    if (iVar11 != 0) {
      *(char *)(iVar11 + 0x36) = (char)iVar10;
      iVar7 = FUN_8002b9ec();
      if (((iVar7 == iVar11) && (FUN_802966d4(iVar11,&local_34), local_34 != 0)) &&
         (*(char *)(local_34 + 0x36) = (char)iVar10, *(char *)(local_34 + 0x36) == '\x01')) {
        *(undefined *)(local_34 + 0x36) = 0;
      }
    }
    bVar1 = *(float *)(param_1 + 0x7a) <= FLOAT_803e17c4;
    (**(code **)(*DAT_803dca50 + 0x38))
              ((double)FLOAT_803e17c4,param_1,auStack36,&local_28,auStack44,&local_30,0);
    if (FLOAT_803e182c <= local_30) {
      local_28 = *(float *)(param_1 + 0xe) - (*(float *)(iVar9 + 0x1c) + FLOAT_803e17c0);
      uVar6 = FUN_800217c0();
      uVar6 = (uVar6 & 0xffff) - ((int)(short)param_1[1] & 0xffffU);
      if (0x8000 < (int)uVar6) {
        uVar6 = uVar6 - 0xffff;
      }
      if ((int)uVar6 < -0x8000) {
        uVar6 = uVar6 + 0xffff;
      }
      local_18 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      uVar6 = (uint)((float)(local_18 - DOUBLE_803e17d8) * FLOAT_803db414);
      local_20 = (longlong)(int)uVar6;
      param_1[1] = param_1[1] +
                   (short)((int)uVar6 >> 3) + (ushort)((int)uVar6 < 0 && (uVar6 & 7) != 0);
    }
    else {
      param_1[1] = 0;
    }
    if (bVar1) {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0xff);
      iVar9 = *(int *)(param_1 + 0x52);
      if (iVar9 != 0) {
        *(undefined *)(iVar9 + 0x36) = 0xff;
        iVar10 = FUN_8002b9ec();
        if (((iVar10 == iVar9) && (FUN_802966d4(iVar9,&local_38), local_38 != 0)) &&
           (*(undefined *)(local_38 + 0x36) = 0xff, *(char *)(local_38 + 0x36) == '\x01')) {
          *(undefined *)(local_38 + 0x36) = 0;
        }
      }
    }
    *(undefined *)(param_1 + 0x9f) = 1;
  }
  iVar9 = FUN_8003687c(*(undefined4 *)(param_1 + 0x52),0,0,0);
  if (iVar9 != 0) {
    FUN_80108194(param_1);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(DAT_803dd548 + 0x14);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(DAT_803dd548 + 0x24);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(DAT_803dd548 + 0x34);
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0);
  }
  FUN_80137948((double)*(float *)(param_1 + 0xe),&DAT_803db9a0);
  FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
               *(undefined4 *)(param_1 + 0x18));
  return;
}

