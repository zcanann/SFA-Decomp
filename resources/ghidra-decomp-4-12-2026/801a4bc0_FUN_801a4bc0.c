// Function: FUN_801a4bc0
// Entry: 801a4bc0
// Size: 1516 bytes

void FUN_801a4bc0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  int iVar3;
  char cVar6;
  uint uVar4;
  uint uVar5;
  byte bVar7;
  undefined uVar8;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar1 = FUN_80286840();
  iVar9 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8002bac4();
  local_28 = DAT_802c2a68;
  local_24 = DAT_802c2a6c;
  local_20 = DAT_802c2a70;
  if ((*(byte *)(iVar9 + 0xc) >> 3 & 1) != 0) {
    iVar3 = FUN_8002e1ac(0x47fae);
    FUN_8017c7ec(iVar3);
    iVar3 = FUN_8002e1ac(0x47f83);
    FUN_8017c7ec(iVar3);
    iVar3 = FUN_8002e1ac(0x47f8f);
    FUN_8017c7ec(iVar3);
    iVar3 = FUN_8002e1ac(0x47fa2);
    FUN_8017c7ec(iVar3);
    iVar3 = FUN_8002e1ac(0x29f2);
    FUN_8017c7ec(iVar3);
    iVar3 = FUN_8002e1ac(0x29f3);
    FUN_8017c7ec(iVar3);
    iVar3 = FUN_8002e1ac(0x29ef);
    FUN_8017c7ec(iVar3);
    iVar3 = FUN_8002e1ac(0x29ee);
    FUN_8017c7ec(iVar3);
    *(byte *)(iVar9 + 0xc) = *(byte *)(iVar9 + 0xc) & 0xf7;
  }
  cVar6 = (**(code **)(*DAT_803dd72c + 0x40))(0x1d);
  uVar10 = extraout_f1;
  if ((cVar6 == '\x01') && (uVar4 = FUN_80020078(0x40), uVar4 != 0)) {
    uVar10 = (**(code **)(*DAT_803dd72c + 0x44))(0x1d,2);
  }
  uVar4 = FUN_80020078(0x974);
  uVar4 = uVar4 & 0xff;
  uVar5 = FUN_80020078(0x975);
  uVar5 = uVar5 & 0xff;
  bVar7 = *(byte *)(iVar9 + 0xc) >> 5 & 1;
  if ((bVar7 == 0) || ((*(byte *)(iVar9 + 0xc) >> 4 & 1) == 0)) {
    if ((bVar7 == 0) && ((*(byte *)(iVar9 + 0xc) >> 4 & 1) == 0)) {
      if ((uVar4 != 0) || (uVar5 != 0)) {
        uVar10 = FUN_8000bb38(0,0x109);
      }
    }
    else if ((uVar4 != 0) && (uVar5 != 0)) {
      uVar10 = FUN_8000bb38(0,0x7e);
    }
  }
  *(byte *)(iVar9 + 0xc) = (byte)(uVar4 << 5) & 0x20 | *(byte *)(iVar9 + 0xc) & 0xdf;
  *(byte *)(iVar9 + 0xc) = (byte)(uVar5 << 4) & 0x10 | *(byte *)(iVar9 + 0xc) & 0xef;
  if (*(int *)(iVar1 + 0xf4) == 0) {
    uVar10 = FUN_80008b74(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                          ,0x56,0,in_r7,in_r8,in_r9,in_r10);
    uVar4 = FUN_80020078(0xd73);
    if (uVar4 == 0) {
      uVar10 = FUN_80008b74(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0xd,0,in_r7,in_r8,in_r9,in_r10);
      uVar10 = FUN_80008b74(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0x11,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80008b74(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1,0xe,0,
                   in_r7,in_r8,in_r9,in_r10);
      FUN_800890e0((double)FLOAT_803e5084,0);
      uVar10 = FUN_800201ac(0xd73,1);
    }
    uVar4 = FUN_80020078(0xdca);
    if (uVar4 != 0) {
      uVar10 = FUN_80008b74(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0xd,0,in_r7,in_r8,in_r9,in_r10);
      uVar10 = FUN_80008b74(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                            iVar1,0x7e,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80008b74(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1,0x7d,0
                   ,in_r7,in_r8,in_r9,in_r10);
      FUN_800890e0((double)FLOAT_803e5084,1);
      FUN_800201ac(0xdca,0);
      FUN_80043604(0,0,1);
    }
    *(undefined4 *)(iVar1 + 0xf4) = 1;
  }
  uVar4 = FUN_80020078(0x94f);
  if ((uVar4 != 0) && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
    FUN_800201ac(0x94e,0);
  }
  uVar4 = FUN_80020078(0x94e);
  if ((uVar4 == 0) || (bVar7 = FUN_80296434(iVar2), bVar7 != 0)) {
    if ((uVar4 == 0) && (bVar7 = FUN_80296434(iVar2), bVar7 == 0)) {
      iVar2 = FUN_8002bac4();
      FUN_80296454(iVar2,1);
    }
  }
  else {
    iVar2 = FUN_8002bac4();
    FUN_80296454(iVar2,0);
  }
  uVar4 = FUN_80020078(0xd3d);
  if (uVar4 != 0) {
    iVar2 = FUN_80057360();
    iVar3 = *DAT_803dd72c;
    (**(code **)(iVar3 + 0x24))(&local_28,0,iVar2,1);
    uVar10 = FUN_800201ac(0xd3d,0);
    uVar10 = FUN_80008b74(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1
                          ,0xd,0,iVar3,in_r8,in_r9,in_r10);
    FUN_80008b74(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,iVar1,0x11,0,
                 iVar3,in_r8,in_r9,in_r10);
    FUN_800890e0((double)FLOAT_803e5080,1);
  }
  iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if (iVar1 == 0x47) {
    if (*(char *)(iVar9 + 0xd) != 'G') {
      FUN_800201ac(0xc0,1);
    }
  }
  else if (*(char *)(iVar9 + 0xd) == 'G') {
    FUN_800201ac(0x1a8,1);
  }
  uVar8 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  *(undefined *)(iVar9 + 0xd) = uVar8;
  FUN_801d84c4(iVar9 + 8,4,-1,-1,0x983,(int *)0xb0);
  FUN_801d84c4(iVar9 + 8,8,-1,-1,0x983,(int *)0x38);
  FUN_801d8650(iVar9 + 8,0x100,-1,-1,0x983,(int *)0x16);
  FUN_801d8650(iVar9 + 8,0x80,-1,-1,0x983,(int *)0x39);
  uVar4 = FUN_80020078(0x983);
  if (uVar4 == 0) {
    uVar4 = FUN_80020078(0xe23);
    if (uVar4 == 0) {
      FUN_801d8650(iVar9 + 8,0x200,-1,-1,0x984,(int *)0xad);
      FUN_801d84c4(iVar9 + 8,0x40,-1,-1,0x984,(int *)0x16);
    }
    uVar4 = FUN_80020078(0x984);
    if (uVar4 != 0) {
      FUN_801d84c4(iVar9 + 8,0x20,-1,-1,0xe23,(int *)0x17);
      FUN_801d8650(iVar9 + 8,0x400,-1,-1,0xe23,(int *)0x16);
    }
  }
  FUN_801d84c4(iVar9 + 8,1,0x1a8,0xc0,0xdb8,(int *)0xae);
  FUN_801d84c4(iVar9 + 8,0x10,-1,-1,0xe1d,(int *)0x36);
  FUN_801d84c4(iVar9 + 8,0x1000,-1,-1,0xe1d,(int *)0xf1);
  FUN_801d84c4(iVar9 + 8,2,-1,-1,0xb46,(int *)0xaf);
  FUN_801d84c4(iVar9 + 8,0x800,-1,-1,0xcbb,(int *)0xc4);
  FUN_8028688c();
  return;
}

