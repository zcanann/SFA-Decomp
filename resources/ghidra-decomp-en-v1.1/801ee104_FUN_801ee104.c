// Function: FUN_801ee104
// Entry: 801ee104
// Size: 1364 bytes

void FUN_801ee104(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  short sVar2;
  short *psVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint *puVar8;
  int iVar9;
  int iVar10;
  undefined8 uVar11;
  undefined4 local_28 [2];
  longlong local_20;
  
  uVar11 = FUN_8028683c();
  psVar3 = (short *)((ulonglong)uVar11 >> 0x20);
  uVar6 = (uint)uVar11;
  local_28[0] = DAT_803e6778;
  iVar10 = *(int *)(psVar3 + 0x5c);
  if (*(char *)(psVar3 + 0x56) == '\x13') {
    uVar4 = FUN_80023d8c(0x24,5);
    FUN_80003494(uVar4,uVar6,0x24);
    *(uint *)(psVar3 + 0x26) = uVar4;
    psVar3[3] = psVar3[3] | 0x2000;
    FUN_8002a8e0((int)psVar3);
  }
  sVar2 = (ushort)*(byte *)(uVar6 + 0x18) << 8;
  *(short *)(iVar10 + 0x40c) = sVar2;
  *(short *)(iVar10 + 0x40e) = sVar2;
  *psVar3 = sVar2;
  FUN_801ecf60(psVar3,iVar10);
  if ((param_3 == 0) && ((*(byte *)(iVar10 + 0x428) >> 5 & 1) != 0)) {
    *(float *)(iVar10 + 0x4b8) = FLOAT_803e6828;
    *(float *)(iVar10 + 0x4c0) = FLOAT_803e6784;
    *(float *)(iVar10 + 0x4bc) = FLOAT_803e682c;
    if (*(char *)(iVar10 + 0x421) == '\x02') {
      local_20 = (longlong)(int)*(float *)(iVar10 + 0x4b8);
      (**(code **)(*DAT_803dd6e8 + 0x58))((int)*(float *)(iVar10 + 0x4b8),0x5cd);
      (**(code **)(*DAT_803dd6e8 + 0x68))((double)FLOAT_803e6830);
    }
  }
  if (*(char *)(uVar6 + 0x19) != '\0') {
    *(byte *)(iVar10 + 0x428) = *(byte *)(iVar10 + 0x428) & 0xfd | 2;
  }
  *(undefined4 *)(iVar10 + 0x38) = 0xffffffff;
  *(undefined4 *)(iVar10 + 0x3c) = 0xffffffff;
  *(undefined4 *)(iVar10 + 0x40) = 0xffffffff;
  *(undefined *)(iVar10 + 0x5c) = *(undefined *)(uVar6 + 0x1c);
  *(undefined *)(iVar10 + 0x5d) = *(undefined *)(uVar6 + 0x1d);
  *(undefined4 *)(iVar10 + 0xc) = *(undefined4 *)(psVar3 + 6);
  *(undefined4 *)(iVar10 + 0x10) = *(undefined4 *)(psVar3 + 8);
  *(undefined4 *)(iVar10 + 0x14) = *(undefined4 *)(psVar3 + 10);
  *(code **)(psVar3 + 0x5e) = FUN_801eba58;
  FUN_800372f8((int)psVar3,10);
  if (param_3 == 0) {
    iVar9 = 0;
    iVar7 = iVar10;
    do {
      iVar5 = FUN_80023d8c(0x640,0x1a);
      *(int *)(iVar7 + 0x4c8) = iVar5;
      iVar7 = iVar7 + 8;
      iVar9 = iVar9 + 1;
    } while (iVar9 < 9);
  }
  *(undefined4 *)(iVar10 + 0x51c) = *(undefined4 *)(psVar3 + 0xc);
  *(undefined4 *)(iVar10 + 0x520) = *(undefined4 *)(psVar3 + 0xe);
  *(undefined4 *)(iVar10 + 0x524) = *(undefined4 *)(psVar3 + 0x10);
  *(float *)(iVar10 + 0x68) = FLOAT_803e6780;
  *(undefined2 *)(iVar10 + 0x448) = *(undefined2 *)(uVar6 + 0x1a);
  *(undefined2 *)(iVar10 + 0x44a) = *(undefined2 *)(uVar6 + 0x1e);
  uVar6 = FUN_80020078((int)*(short *)(iVar10 + 0x44a));
  if (uVar6 != 0) {
    *(byte *)(iVar10 + 0x428) = *(byte *)(iVar10 + 0x428) & 0xfb | 4;
  }
  *(float *)(iVar10 + 0x438) = FLOAT_803e67b4;
  fVar1 = FLOAT_803e6780;
  *(float *)(iVar10 + 0x3f4) = FLOAT_803e6780;
  *(float *)(iVar10 + 0x3f8) = fVar1;
  *(float *)(iVar10 + 0x18) = FLOAT_803e68e0;
  *(float *)(iVar10 + 0x1c) = fVar1;
  *(float *)(iVar10 + 0x20) = FLOAT_803e685c;
  *(float *)(iVar10 + 0x24) = FLOAT_803e68e8;
  *(undefined *)(iVar10 + 0x65) = 0xff;
  fVar1 = FLOAT_803e6830;
  *(float *)(iVar10 + 0x464) = FLOAT_803e6830;
  *(float *)(iVar10 + 0x468) = fVar1;
  *(undefined2 *)(iVar10 + 0x440) = 0x436;
  sVar2 = psVar3[0x23];
  if (sVar2 == 0x38c) {
    *(undefined *)(iVar10 + 0x434) = 0;
    *(float *)(iVar10 + 0x46c) = FLOAT_803dcd2c;
    *(undefined2 *)(iVar10 + 0x440) = 0x11a;
    goto LAB_801ee4cc;
  }
  if (sVar2 < 0x38c) {
    if (sVar2 == 0x16c) {
      *(undefined *)(iVar10 + 0x434) = 1;
      *(undefined *)(iVar10 + 0x435) = 0;
      *(float *)(iVar10 + 0x1c) = FLOAT_803e67ac;
      *(float *)(iVar10 + 0x18) = FLOAT_803e68ec;
      *(undefined *)(iVar10 + 0x65) = 1;
      *(float *)(iVar10 + 0x46c) = FLOAT_803e6788;
      goto LAB_801ee4cc;
    }
    if ((0x16b < sVar2) && (sVar2 == 0x16f)) {
      *(undefined *)(iVar10 + 0x434) = 1;
      *(undefined *)(iVar10 + 0x58) = 1;
      *(undefined *)(iVar10 + 0x435) = 1;
      *(undefined *)(iVar10 + 0x65) = 2;
      *(float *)(iVar10 + 0x46c) = FLOAT_803e6788;
      goto LAB_801ee4cc;
    }
  }
  else {
    if (sVar2 == 0x4d4) {
      *(undefined *)(iVar10 + 0x434) = 0;
      *(undefined *)(iVar10 + 0x435) = 2;
      *(float *)(iVar10 + 0x1c) = FLOAT_803e67e0;
      *(float *)(iVar10 + 0x18) = FLOAT_803e68f4;
      *(float *)(iVar10 + 0x46c) = FLOAT_803dcd28;
      goto LAB_801ee4cc;
    }
    if (sVar2 < 0x4d4) {
      if (sVar2 == 0x38e) {
        *(undefined *)(iVar10 + 0x434) = 0;
        *(undefined *)(iVar10 + 0x435) = 1;
        *(float *)(iVar10 + 0x1c) = FLOAT_803e67e0;
        *(float *)(iVar10 + 0x18) = FLOAT_803e68f4;
        *(float *)(iVar10 + 0x46c) = FLOAT_803e68f8 * FLOAT_803dcd28;
        goto LAB_801ee4cc;
      }
      if (sVar2 < 0x38e) {
        *(undefined *)(iVar10 + 0x434) = 0;
        *(undefined *)(iVar10 + 0x435) = 0;
        *(float *)(iVar10 + 0x1c) = FLOAT_803e67ac;
        *(float *)(iVar10 + 0x18) = FLOAT_803e68ec;
        *(float *)(iVar10 + 0x46c) = FLOAT_803e68f0 * FLOAT_803dcd28;
        goto LAB_801ee4cc;
      }
    }
  }
  *(undefined *)(iVar10 + 0x434) = 1;
  *(float *)(iVar10 + 0x46c) = FLOAT_803e68e8;
  *(undefined2 *)(iVar10 + 0x440) = 0x11a;
LAB_801ee4cc:
  *(undefined4 *)(iVar10 + 0x47c) = *(undefined4 *)(iVar10 + 0x464);
  *(undefined4 *)(iVar10 + 0x470) = *(undefined4 *)(iVar10 + 0x464);
  *(undefined4 *)(iVar10 + 0x480) = *(undefined4 *)(iVar10 + 0x468);
  *(undefined4 *)(iVar10 + 0x474) = *(undefined4 *)(iVar10 + 0x468);
  *(undefined4 *)(iVar10 + 0x484) = *(undefined4 *)(iVar10 + 0x46c);
  *(undefined4 *)(iVar10 + 0x478) = *(undefined4 *)(iVar10 + 0x46c);
  *(uint *)(iVar10 + 0x60) = (uint)*(byte *)(iVar10 + 0x434) * 6 + -0x7fcd6e3c;
  if (*(char *)(iVar10 + 0x434) == '\0') {
    if ((*(byte *)(iVar10 + 0x428) >> 1 & 1) == 0) {
      *(byte *)(iVar10 + 0x428) = *(byte *)(iVar10 + 0x428) & 0xdf | 0x20;
      *(float *)(iVar10 + 0x4c4) = FLOAT_803e6780;
    }
    *(float *)(iVar10 + 0x538) = FLOAT_803e68fc;
  }
  else {
    *(float *)(iVar10 + 0x538) = FLOAT_803e680c;
  }
  puVar8 = (uint *)(iVar10 + 0x178);
  *(undefined *)(iVar10 + 0x3d3) = 1;
  (**(code **)(*DAT_803dd728 + 4))(puVar8,0,0x48607,1);
  (**(code **)(*DAT_803dd728 + 0xc))(puVar8,4,&DAT_80329120,&DAT_80329150,local_28);
  if (((*(byte *)(iVar10 + 0x428) >> 1 & 1) == 0) || (*(char *)(iVar10 + 0x65) == -1)) {
    (**(code **)(*DAT_803dd728 + 8))(puVar8,1,&DAT_80329160,&FLOAT_803dcd20,8);
  }
  else {
    FUN_800e7f08(puVar8,1,0x80329160,0x803dcd20,8,*(char *)(iVar10 + 0x65));
  }
  local_20 = (longlong)(int)(FLOAT_803e6900 + FLOAT_803dcd20);
  *(char *)(iVar10 + 0x3dc) = (char)(int)(FLOAT_803e6900 + FLOAT_803dcd20);
  (**(code **)(*DAT_803dd728 + 0x20))(psVar3,puVar8);
  FUN_80286888();
  return;
}

