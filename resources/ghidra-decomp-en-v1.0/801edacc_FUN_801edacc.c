// Function: FUN_801edacc
// Entry: 801edacc
// Size: 1364 bytes

void FUN_801edacc(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  short sVar2;
  short *psVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  undefined4 local_28 [2];
  longlong local_20;
  
  uVar9 = FUN_802860d8();
  psVar3 = (short *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  local_28[0] = DAT_803e5ae0;
  iVar8 = *(int *)(psVar3 + 0x5c);
  if (*(char *)(psVar3 + 0x56) == '\x13') {
    uVar4 = FUN_80023cc8(0x24,5,0);
    FUN_80003494(uVar4,iVar5,0x24);
    *(undefined4 *)(psVar3 + 0x26) = uVar4;
    psVar3[3] = psVar3[3] | 0x2000;
    FUN_8002a808(psVar3);
  }
  sVar2 = (ushort)*(byte *)(iVar5 + 0x18) << 8;
  *(short *)(iVar8 + 0x40c) = sVar2;
  *(short *)(iVar8 + 0x40e) = sVar2;
  *psVar3 = sVar2;
  FUN_801ec928(psVar3,iVar8);
  if ((param_3 == 0) && ((*(byte *)(iVar8 + 0x428) >> 5 & 1) != 0)) {
    *(float *)(iVar8 + 0x4b8) = FLOAT_803e5b90;
    *(float *)(iVar8 + 0x4c0) = FLOAT_803e5aec;
    *(float *)(iVar8 + 0x4bc) = FLOAT_803e5b94;
    if (*(char *)(iVar8 + 0x421) == '\x02') {
      local_20 = (longlong)(int)*(float *)(iVar8 + 0x4b8);
      (**(code **)(*DAT_803dca68 + 0x58))((int)*(float *)(iVar8 + 0x4b8),0x5cd);
      (**(code **)(*DAT_803dca68 + 0x68))((double)FLOAT_803e5b98);
    }
  }
  if (*(char *)(iVar5 + 0x19) != '\0') {
    *(byte *)(iVar8 + 0x428) = *(byte *)(iVar8 + 0x428) & 0xfd | 2;
  }
  *(undefined4 *)(iVar8 + 0x38) = 0xffffffff;
  *(undefined4 *)(iVar8 + 0x3c) = 0xffffffff;
  *(undefined4 *)(iVar8 + 0x40) = 0xffffffff;
  *(undefined *)(iVar8 + 0x5c) = *(undefined *)(iVar5 + 0x1c);
  *(undefined *)(iVar8 + 0x5d) = *(undefined *)(iVar5 + 0x1d);
  *(undefined4 *)(iVar8 + 0xc) = *(undefined4 *)(psVar3 + 6);
  *(undefined4 *)(iVar8 + 0x10) = *(undefined4 *)(psVar3 + 8);
  *(undefined4 *)(iVar8 + 0x14) = *(undefined4 *)(psVar3 + 10);
  *(code **)(psVar3 + 0x5e) = FUN_801eb420;
  FUN_80037200(psVar3,10);
  if (param_3 == 0) {
    iVar7 = 0;
    iVar6 = iVar8;
    do {
      uVar4 = FUN_80023cc8(0x640,0x1a,0);
      *(undefined4 *)(iVar6 + 0x4c8) = uVar4;
      iVar6 = iVar6 + 8;
      iVar7 = iVar7 + 1;
    } while (iVar7 < 9);
  }
  *(undefined4 *)(iVar8 + 0x51c) = *(undefined4 *)(psVar3 + 0xc);
  *(undefined4 *)(iVar8 + 0x520) = *(undefined4 *)(psVar3 + 0xe);
  *(undefined4 *)(iVar8 + 0x524) = *(undefined4 *)(psVar3 + 0x10);
  *(float *)(iVar8 + 0x68) = FLOAT_803e5ae8;
  *(undefined2 *)(iVar8 + 0x448) = *(undefined2 *)(iVar5 + 0x1a);
  *(undefined2 *)(iVar8 + 0x44a) = *(undefined2 *)(iVar5 + 0x1e);
  iVar5 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x44a));
  if (iVar5 != 0) {
    *(byte *)(iVar8 + 0x428) = *(byte *)(iVar8 + 0x428) & 0xfb | 4;
  }
  *(float *)(iVar8 + 0x438) = FLOAT_803e5b1c;
  fVar1 = FLOAT_803e5ae8;
  *(float *)(iVar8 + 0x3f4) = FLOAT_803e5ae8;
  *(float *)(iVar8 + 0x3f8) = fVar1;
  *(float *)(iVar8 + 0x18) = FLOAT_803e5c48;
  *(float *)(iVar8 + 0x1c) = fVar1;
  *(float *)(iVar8 + 0x20) = FLOAT_803e5bc4;
  *(float *)(iVar8 + 0x24) = FLOAT_803e5c50;
  *(undefined *)(iVar8 + 0x65) = 0xff;
  fVar1 = FLOAT_803e5b98;
  *(float *)(iVar8 + 0x464) = FLOAT_803e5b98;
  *(float *)(iVar8 + 0x468) = fVar1;
  *(undefined2 *)(iVar8 + 0x440) = 0x436;
  sVar2 = psVar3[0x23];
  if (sVar2 == 0x38c) {
    *(undefined *)(iVar8 + 0x434) = 0;
    *(float *)(iVar8 + 0x46c) = FLOAT_803dc0c4;
    *(undefined2 *)(iVar8 + 0x440) = 0x11a;
    goto LAB_801ede94;
  }
  if (sVar2 < 0x38c) {
    if (sVar2 == 0x16c) {
      *(undefined *)(iVar8 + 0x434) = 1;
      *(undefined *)(iVar8 + 0x435) = 0;
      *(float *)(iVar8 + 0x1c) = FLOAT_803e5b14;
      *(float *)(iVar8 + 0x18) = FLOAT_803e5c54;
      *(undefined *)(iVar8 + 0x65) = 1;
      *(float *)(iVar8 + 0x46c) = FLOAT_803e5af0;
      goto LAB_801ede94;
    }
    if ((0x16b < sVar2) && (sVar2 == 0x16f)) {
      *(undefined *)(iVar8 + 0x434) = 1;
      *(undefined *)(iVar8 + 0x58) = 1;
      *(undefined *)(iVar8 + 0x435) = 1;
      *(undefined *)(iVar8 + 0x65) = 2;
      *(float *)(iVar8 + 0x46c) = FLOAT_803e5af0;
      goto LAB_801ede94;
    }
  }
  else {
    if (sVar2 == 0x4d4) {
      *(undefined *)(iVar8 + 0x434) = 0;
      *(undefined *)(iVar8 + 0x435) = 2;
      *(float *)(iVar8 + 0x1c) = FLOAT_803e5b48;
      *(float *)(iVar8 + 0x18) = FLOAT_803e5c5c;
      *(float *)(iVar8 + 0x46c) = FLOAT_803dc0c0;
      goto LAB_801ede94;
    }
    if (sVar2 < 0x4d4) {
      if (sVar2 == 0x38e) {
        *(undefined *)(iVar8 + 0x434) = 0;
        *(undefined *)(iVar8 + 0x435) = 1;
        *(float *)(iVar8 + 0x1c) = FLOAT_803e5b48;
        *(float *)(iVar8 + 0x18) = FLOAT_803e5c5c;
        *(float *)(iVar8 + 0x46c) = FLOAT_803e5c60 * FLOAT_803dc0c0;
        goto LAB_801ede94;
      }
      if (sVar2 < 0x38e) {
        *(undefined *)(iVar8 + 0x434) = 0;
        *(undefined *)(iVar8 + 0x435) = 0;
        *(float *)(iVar8 + 0x1c) = FLOAT_803e5b14;
        *(float *)(iVar8 + 0x18) = FLOAT_803e5c54;
        *(float *)(iVar8 + 0x46c) = FLOAT_803e5c58 * FLOAT_803dc0c0;
        goto LAB_801ede94;
      }
    }
  }
  *(undefined *)(iVar8 + 0x434) = 1;
  *(float *)(iVar8 + 0x46c) = FLOAT_803e5c50;
  *(undefined2 *)(iVar8 + 0x440) = 0x11a;
LAB_801ede94:
  *(undefined4 *)(iVar8 + 0x47c) = *(undefined4 *)(iVar8 + 0x464);
  *(undefined4 *)(iVar8 + 0x470) = *(undefined4 *)(iVar8 + 0x464);
  *(undefined4 *)(iVar8 + 0x480) = *(undefined4 *)(iVar8 + 0x468);
  *(undefined4 *)(iVar8 + 0x474) = *(undefined4 *)(iVar8 + 0x468);
  *(undefined4 *)(iVar8 + 0x484) = *(undefined4 *)(iVar8 + 0x46c);
  *(undefined4 *)(iVar8 + 0x478) = *(undefined4 *)(iVar8 + 0x46c);
  *(uint *)(iVar8 + 0x60) = (uint)*(byte *)(iVar8 + 0x434) * 6 + -0x7fcd7a7c;
  if (*(char *)(iVar8 + 0x434) == '\0') {
    if ((*(byte *)(iVar8 + 0x428) >> 1 & 1) == 0) {
      *(byte *)(iVar8 + 0x428) = *(byte *)(iVar8 + 0x428) & 0xdf | 0x20;
      *(float *)(iVar8 + 0x4c4) = FLOAT_803e5ae8;
    }
    *(float *)(iVar8 + 0x538) = FLOAT_803e5c64;
  }
  else {
    *(float *)(iVar8 + 0x538) = FLOAT_803e5b74;
  }
  iVar5 = iVar8 + 0x178;
  *(undefined *)(iVar8 + 0x3d3) = 1;
  (**(code **)(*DAT_803dcaa8 + 4))(iVar5,0,0x48607,1);
  (**(code **)(*DAT_803dcaa8 + 0xc))(iVar5,4,&DAT_803284e0,&DAT_80328510,local_28);
  if (((*(byte *)(iVar8 + 0x428) >> 1 & 1) == 0) || (*(char *)(iVar8 + 0x65) == -1)) {
    (**(code **)(*DAT_803dcaa8 + 8))(iVar5,1,&DAT_80328520,&FLOAT_803dc0b8,8);
  }
  else {
    FUN_800e7c84(iVar5,1,&DAT_80328520,&FLOAT_803dc0b8,8);
  }
  local_20 = (longlong)(int)(FLOAT_803e5c68 + FLOAT_803dc0b8);
  *(char *)(iVar8 + 0x3dc) = (char)(int)(FLOAT_803e5c68 + FLOAT_803dc0b8);
  (**(code **)(*DAT_803dcaa8 + 0x20))(psVar3,iVar5);
  FUN_80286124();
  return;
}

