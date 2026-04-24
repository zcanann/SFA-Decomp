// Function: FUN_80110ec4
// Entry: 80110ec4
// Size: 1532 bytes

void FUN_80110ec4(short *param_1)

{
  int iVar1;
  int iVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  double local_78;
  double local_70;
  double local_68;
  double local_60;
  double local_58;
  undefined4 local_50;
  uint uStack76;
  double local_48;
  double local_40;
  double local_38;
  undefined4 local_30;
  uint uStack44;
  double local_28;
  double local_20;
  
  iVar7 = *(int *)(param_1 + 0x52);
  *(float *)(param_1 + 0xc) = DAT_803a43c0 * DAT_803a43e4;
  *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + DAT_803a43cc;
  *(float *)(param_1 + 0xe) = DAT_803a43c4 * DAT_803a43e8;
  *(float *)(param_1 + 0xe) = *(float *)(param_1 + 0xe) + DAT_803a43d0;
  *(float *)(param_1 + 0x10) = *(float *)(iVar7 + 0x20) + DAT_803a43f8;
  if (*(char *)(iVar7 + 0xac) != '&') {
    fVar3 = DAT_803a4400 / DAT_803a43fc - FLOAT_803e1ba0;
    if (FLOAT_803e1ba4 <= fVar3) {
      local_78 = (double)CONCAT44(0x43300000,-(uint)DAT_803a441b ^ 0x80000000);
      *(float *)(param_1 + 0x10) =
           (float)(local_78 - DOUBLE_803e1bb8) * fVar3 + *(float *)(param_1 + 0x10);
    }
    else {
      local_78 = (double)CONCAT44(0x43300000,-(uint)DAT_803a441a ^ 0x80000000);
      *(float *)(param_1 + 0x10) =
           (float)(local_78 - DOUBLE_803e1bb8) * fVar3 + *(float *)(param_1 + 0x10);
    }
  }
  local_78 = (double)CONCAT44(0x43300000,(int)DAT_803a4414 ^ 0x80000000);
  iVar1 = (int)((float)(local_78 - DOUBLE_803e1bb8) * DAT_803a4404);
  local_70 = (double)(longlong)iVar1;
  local_68 = (double)CONCAT44(0x43300000,(int)DAT_803a4416 ^ 0x80000000);
  iVar2 = (int)((float)(local_68 - DOUBLE_803e1bb8) * DAT_803a4408);
  local_60 = (double)(longlong)iVar2;
  iVar4 = FUN_8022d750(iVar7);
  if (iVar4 == 0) {
    iVar7 = FUN_8022d710(iVar7);
    if (iVar7 == 0) {
      local_20 = (double)CONCAT44(0x43300000,(int)DAT_803a4418 ^ 0x80000000);
      iVar7 = (int)((float)(local_20 - DOUBLE_803e1bb8) * DAT_803a440c);
      local_28 = (double)(longlong)iVar7;
      uStack44 = iVar7 - ((int)param_1[2] & 0xffffU);
      if (0x8000 < (int)uStack44) {
        uStack44 = uStack44 - 0xffff;
      }
      if ((int)uStack44 < -0x8000) {
        uStack44 = uStack44 + 0xffff;
      }
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_38 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
      iVar7 = (int)((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1bb8) *
                    FLOAT_803db414 * FLOAT_803e1bac + (float)(local_38 - DOUBLE_803e1bb8));
      local_40 = (double)(longlong)iVar7;
      param_1[2] = (short)iVar7;
      uVar5 = iVar1 - ((int)*param_1 & 0xffffU);
      if (0x8000 < (int)uVar5) {
        uVar5 = uVar5 - 0xffff;
      }
      if ((int)uVar5 < -0x8000) {
        uVar5 = uVar5 + 0xffff;
      }
      local_48 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      uStack76 = (int)*param_1 ^ 0x80000000;
      local_50 = 0x43300000;
      iVar7 = (int)((float)(local_48 - DOUBLE_803e1bb8) * FLOAT_803db414 * FLOAT_803e1bac +
                   (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e1bb8));
      local_58 = (double)(longlong)iVar7;
      *param_1 = (short)iVar7;
      uVar5 = iVar2 - ((int)param_1[1] & 0xffffU);
      if (0x8000 < (int)uVar5) {
        uVar5 = uVar5 - 0xffff;
      }
      if ((int)uVar5 < -0x8000) {
        uVar5 = uVar5 + 0xffff;
      }
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_68 = (double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000);
      iVar7 = (int)((float)(local_60 - DOUBLE_803e1bb8) * FLOAT_803db414 * FLOAT_803e1bac +
                   (float)(local_68 - DOUBLE_803e1bb8));
      local_70 = (double)(longlong)iVar7;
      param_1[1] = (short)iVar7;
    }
    else {
      DAT_803a4410 = DAT_803a4410 * FLOAT_803e1bb0;
      local_20 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
      iVar7 = (int)(DAT_803a4410 * FLOAT_803db414 + (float)(local_20 - DOUBLE_803e1bb8));
      local_28 = (double)(longlong)iVar7;
      param_1[2] = (short)iVar7;
    }
  }
  else {
    DAT_803a4410 = FLOAT_803e1ba8;
    (**(code **)(*DAT_803dca50 + 0x38))
              ((double)FLOAT_803e1ba4,param_1,&local_7c,&local_80,&local_84,&local_88,0);
    local_60 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
    iVar7 = (int)(DAT_803a4410 * FLOAT_803db414 + (float)(local_60 - DOUBLE_803e1bb8));
    local_68 = (double)(longlong)iVar7;
    param_1[2] = (short)iVar7;
    uVar5 = FUN_800217c0((double)local_7c,(double)local_84);
    uVar6 = FUN_800217c0((double)local_80,(double)local_88);
    uVar5 = (0x8000 - (uVar5 & 0xffff)) - ((int)*param_1 & 0xffffU);
    if (0x8000 < (int)uVar5) {
      uVar5 = uVar5 - 0xffff;
    }
    if ((int)uVar5 < -0x8000) {
      uVar5 = uVar5 + 0xffff;
    }
    local_70 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    uVar5 = (uint)((float)(local_70 - DOUBLE_803e1bb8) * FLOAT_803db414);
    local_78 = (double)(longlong)(int)uVar5;
    local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    uStack76 = (int)*param_1 ^ 0x80000000;
    local_50 = 0x43300000;
    iVar7 = (int)((float)(local_58 - DOUBLE_803e1bb8) * FLOAT_803e1bac +
                 (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e1bb8));
    local_48 = (double)(longlong)iVar7;
    *param_1 = (short)iVar7;
    uVar5 = (uVar6 & 0xffff) - ((int)param_1[1] & 0xffffU);
    if (0x8000 < (int)uVar5) {
      uVar5 = uVar5 - 0xffff;
    }
    if ((int)uVar5 < -0x8000) {
      uVar5 = uVar5 + 0xffff;
    }
    local_40 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    uStack44 = (uint)((float)(local_40 - DOUBLE_803e1bb8) * FLOAT_803db414);
    local_38 = (double)(longlong)(int)uStack44;
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = (double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000);
    iVar7 = (int)((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e1bb8) * FLOAT_803e1bac
                 + (float)(local_28 - DOUBLE_803e1bb8));
    local_20 = (double)(longlong)iVar7;
    param_1[1] = (short)iVar7;
  }
  FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
               *(undefined4 *)(param_1 + 0x18));
  return;
}

