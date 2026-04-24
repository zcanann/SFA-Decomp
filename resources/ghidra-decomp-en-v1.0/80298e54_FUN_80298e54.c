// Function: FUN_80298e54
// Entry: 80298e54
// Size: 1616 bytes

/* WARNING: Removing unreachable block (ram,0x8029947c) */

undefined4 FUN_80298e54(double param_1,int param_2,int param_3)

{
  short sVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  undefined4 uVar8;
  undefined8 in_f31;
  double dVar9;
  undefined2 local_38;
  undefined local_36;
  undefined local_35;
  undefined4 local_30;
  uint uStack44;
  double local_28;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar7 = *(int *)(param_2 + 0xb8);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    FUN_80035e8c();
  }
  FUN_8011f3c8(10);
  fVar2 = FLOAT_803e7ea4;
  *(float *)(param_3 + 0x294) = FLOAT_803e7ea4;
  *(float *)(param_3 + 0x284) = fVar2;
  *(float *)(param_3 + 0x280) = fVar2;
  *(float *)(param_2 + 0x24) = fVar2;
  *(float *)(param_2 + 0x28) = fVar2;
  *(float *)(param_2 + 0x2c) = fVar2;
  sVar1 = *(short *)(param_2 + 0xa0);
  if (sVar1 == 0xb1) {
    FUN_8011f3ec(2);
    FUN_8018a20c(DAT_803de434,0);
    if ((*(ushort *)(iVar7 + 0x6e2) & 0x100) == 0) {
      if ((*(ushort *)(iVar7 + 0x6e2) & 0x200) != 0) {
        FUN_80014b3c(0,0x200);
        FUN_8000bb18(param_2,0x218);
        FUN_80030334((double)FLOAT_803e7ea4,param_2,0xd1,0);
        *(float *)(param_3 + 0x2a0) = FLOAT_803e7f4c;
      }
    }
    else {
      FUN_80014b3c(0,0x100);
      FLOAT_803de488 = FLOAT_803e7ed8;
      FUN_80030334((double)FLOAT_803e7ea4,param_2,0xac,0);
      *(float *)(param_3 + 0x2a0) = FLOAT_803e7ea4;
    }
  }
  else if (sVar1 < 0xb1) {
    if (sVar1 == 0xac) {
      FUN_8011f3ec(2);
      FLOAT_803de488 = FLOAT_803de488 - FLOAT_803e7ee0;
      if (((*(ushort *)(iVar7 + 0x6e4) & 0x100) == 0) && (iVar3 = FUN_80080204(), iVar3 == 0))
      goto LAB_80299158;
      FUN_80014b3c(0,0x100);
      FLOAT_803de460 = (float)((double)FLOAT_803de460 - param_1);
      if (FLOAT_803de460 < FLOAT_803e7ea4) {
        if (*(short *)(iVar7 + 0x81a) == 0) {
          uVar5 = 0x2d3;
        }
        else {
          uVar5 = 0x2b;
        }
        FUN_8000bb18(param_2,uVar5);
        uStack44 = FUN_800221a0(10,0x12);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        FLOAT_803de460 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e7ec0);
      }
      iVar3 = FUN_80189f44(DAT_803de434);
      if (iVar3 == 1) {
LAB_80299134:
        FLOAT_803de488 = FLOAT_803de488 + FLOAT_803e7f54;
      }
      else if (iVar3 < 1) {
        if (iVar3 < 0) goto LAB_80299134;
        FLOAT_803de488 = FLOAT_803de488 + FLOAT_803e7f58;
      }
      else {
        if (2 < iVar3) goto LAB_80299134;
        FLOAT_803de488 = FLOAT_803de488 + FLOAT_803e7f50;
      }
LAB_80299158:
      if (FLOAT_803de488 <= FLOAT_803e7f5c) {
        if (FLOAT_803de488 < FLOAT_803e7f60) {
          FLOAT_803de488 = FLOAT_803e7f60;
        }
      }
      else {
        FLOAT_803de488 = FLOAT_803e7f5c;
      }
      uStack44 = FUN_8018a200(DAT_803de434);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      uVar6 = (uint)((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e7ec0) +
                    FLOAT_803de488);
      local_28 = (double)(longlong)(int)uVar6;
      if ((int)uVar6 < 1) {
        FLOAT_803de488 = FLOAT_803e7ea4;
        uVar6 = 0;
        FUN_80030334(param_2,0xb1,0);
        *(float *)(param_3 + 0x2a0) = FLOAT_803e7ef8;
      }
      else if (0x800 < (int)uVar6) {
        uVar6 = 0x800;
      }
      local_28 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      dVar9 = (double)((float)(local_28 - DOUBLE_803e7ec0) / FLOAT_803e7f64);
      if (dVar9 < (double)FLOAT_803e7f68) {
        uVar4 = FUN_800221a0(0xffffff9c,100);
        local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        FUN_80030304((double)(float)(dVar9 + (double)((float)(local_28 - DOUBLE_803e7ec0) /
                                                     FLOAT_803e7f70)),param_2);
      }
      else {
        FUN_80189c68(DAT_803de434);
        if (*(short *)(iVar7 + 0x81a) == 0) {
          uVar5 = 0x2d3;
        }
        else {
          uVar5 = 0x2b;
        }
        FUN_8000bb18(param_2,uVar5);
        FUN_80030334((double)FLOAT_803e7ea4,param_2,0xd0,0);
        *(float *)(param_3 + 0x2a0) = FLOAT_803e7f6c;
      }
      FUN_8018a20c(DAT_803de434,uVar6);
    }
    else if (sVar1 < 0xac) {
      if (sVar1 < 0xab) {
LAB_80299390:
        FUN_80030334((double)FLOAT_803e7ea4,param_2,0xab,0);
        *(float *)(param_3 + 0x2a0) = FLOAT_803e7f40;
        FUN_80189f5c(DAT_803de434,param_2 + 0xc,param_2 + 0x14);
        *(short *)(iVar7 + 0x478) = *DAT_803de434 + -0x8000;
        *(undefined2 *)(iVar7 + 0x484) = *(undefined2 *)(iVar7 + 0x478);
        if ((DAT_803de44c != 0) && ((*(byte *)(iVar7 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar7 + 0x8b4) = 4;
          *(byte *)(iVar7 + 0x3f4) = *(byte *)(iVar7 + 0x3f4) & 0xf7 | 8;
        }
        FLOAT_803de488 = FLOAT_803e7ea4;
        DAT_803de48c = '\0';
        FLOAT_803de460 = FLOAT_803e7ea4;
        if ((*(char *)(iVar7 + 0x8c8) != 'H') && (*(char *)(iVar7 + 0x8c8) != 'G')) {
          local_38 = 0;
          local_36 = 0;
          local_35 = 1;
          (**(code **)(*DAT_803dca50 + 0x1c))(0x43,1,0,4,&local_38,0,0xff);
        }
      }
      else {
        FUN_8011f3ec(2);
        if ((DAT_803de48c == '\0') && (FLOAT_803e7e9c < *(float *)(param_2 + 0x98))) {
          FUN_8000bb18(param_2,0x218);
          DAT_803de48c = '\x01';
        }
        if (*(char *)(param_3 + 0x346) != '\0') {
          FUN_80030334((double)FLOAT_803e7ea4,param_2,0xb1,0);
          *(float *)(param_3 + 0x2a0) = FLOAT_803e7ef8;
        }
      }
    }
    else {
      if (0xad < sVar1) goto LAB_80299390;
      if (*(char *)(param_3 + 0x346) != '\0') {
        *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) | 0x800000;
        *(code **)(param_3 + 0x308) = FUN_802a514c;
        uVar5 = 2;
        goto LAB_8029947c;
      }
    }
  }
  else if (sVar1 == 0xd0) {
    FUN_8018a20c(DAT_803de434,0x800);
    if (*(char *)(param_3 + 0x346) != '\0') {
      FUN_8000bb18(param_2,0x109);
      FUN_80030334((double)FLOAT_803e7ea4,param_2,0xb2,0);
      *(float *)(param_3 + 0x2a0) = FLOAT_803e7ef8;
    }
  }
  else if (sVar1 < 0xd0) {
    if (0xb2 < sVar1) goto LAB_80299390;
    FUN_8018a20c(DAT_803de434,0x800);
    if ((*(ushort *)(iVar7 + 0x6e2) & 0x200) != 0) {
      FUN_80014b3c(0,0x200);
      FUN_8000bb18(param_2,0x218);
      FUN_80030334((double)FLOAT_803e7ea4,param_2,0xad,0);
      *(float *)(param_3 + 0x2a0) = FLOAT_803e7f4c;
    }
  }
  else {
    if (0xd1 < sVar1) goto LAB_80299390;
    if (*(char *)(param_3 + 0x346) != '\0') {
      *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) | 0x800000;
      *(code **)(param_3 + 0x308) = FUN_802a514c;
      uVar5 = 2;
      goto LAB_8029947c;
    }
  }
  uVar5 = 0;
LAB_8029947c:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  return uVar5;
}

