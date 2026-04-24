// Function: FUN_80072f78
// Entry: 80072f78
// Size: 2160 bytes

void FUN_80072f78(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  code *pcVar4;
  uint uVar5;
  uint uVar6;
  int *piVar7;
  uint uVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  uint3 local_90;
  uint3 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  float afStack_7c [12];
  float afStack_4c [3];
  float local_40;
  float local_30;
  float local_20;
  
  uVar11 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar11 >> 0x20);
  piVar7 = (int *)uVar11;
  iVar9 = *piVar7;
  iVar2 = FUN_800284e8(iVar9,param_3);
  iVar3 = FUN_8006c8c0();
  FUN_8006c86c(0);
  FUN_8004c460(iVar3,1);
  FUN_8006c820(2);
  FUN_8025d8c4((float *)&DAT_80397480,0x55,0);
  FUN_80258674(1,0,0,0,0,0x55);
  if ((iVar9 == 0) || (*(short *)(iVar9 + 0xe6) != 0)) {
    FUN_80247a7c((double)FLOAT_803dc318,(double)FLOAT_803dc318,(double)FLOAT_803dfb5c,afStack_4c);
    local_20 = FLOAT_803dfb64;
    FUN_80247a48((double)FLOAT_803dfb78,(double)FLOAT_803dfb78,(double)FLOAT_803dfb5c,afStack_7c);
    FUN_80247618(afStack_7c,afStack_4c,afStack_4c);
  }
  else {
    dVar10 = (double)FLOAT_803dfb5c;
    FUN_80247a7c(dVar10,dVar10,dVar10,afStack_4c);
    local_40 = FLOAT_803dfb78;
    local_30 = FLOAT_803dfb78;
    local_20 = FLOAT_803dfb64;
  }
  FUN_8025d8c4(afStack_4c,0x52,0);
  FUN_80258674(0,0,1,0x1e,1,0x52);
  FUN_80247a7c((double)FLOAT_803dc320,(double)FLOAT_803dc320,(double)FLOAT_803dfb5c,afStack_4c);
  local_20 = FLOAT_803dfb64;
  FUN_8025d8c4(afStack_4c,0x4f,0);
  FUN_80258674(2,0,4,0x3c,0,0x4f);
  FUN_8025bd1c(0,1,1);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,(float *)&DAT_8030f618,-1);
  FUN_8025b94c(0,0,0,7,1,0,0,0,0,0);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,0xf,0xf,0xf,8);
  FUN_8025c224(0,7,7,7,6);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025be80(1);
  FUN_8025c828(1,2,2,0xff);
  FUN_8025c1a4(1,0,8,0xe,0xf);
  FUN_8025c224(1,7,7,7,0);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  FUN_8025be54(1);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_80258944(3);
  FUN_8025ca04(2);
  local_80 = CONCAT31(local_80._0_3_,
                      (char)((uint)*(byte *)(iVar2 + 0xc) * (uint)*(byte *)(iVar1 + 0x37) >> 8));
  local_84 = local_80;
  FUN_8025c510(0,(byte *)&local_84);
  FUN_8025c5f0(0,0x1c);
  local_88 = DAT_803dc31c;
  FUN_8025c510(1,(byte *)&local_88);
  FUN_8025c584(1,0xd);
  pcVar4 = (code *)FUN_80028588((int)piVar7);
  if (pcVar4 == (code *)0x0) {
    uVar8 = 1;
    if (((*(char *)(iVar1 + 0x37) == -1) && ((*(uint *)(iVar2 + 0x3c) & 0x40000000) == 0)) &&
       (*(char *)(iVar2 + 0xc) == -1)) {
      if ((*(uint *)(iVar2 + 0x3c) & 0x400) == 0) {
        FUN_8025cce8(0,1,0,5);
        if ((*(ushort *)(iVar9 + 2) & 0x400) == 0) {
          if (((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) ||
             ((DAT_803ddc92 != '\x01' || (DAT_803ddc9a == '\0')))) {
            FUN_8025ce6c(1,3,1);
            DAT_803ddc98 = '\x01';
            DAT_803ddc94 = 3;
            DAT_803ddc92 = '\x01';
            DAT_803ddc9a = '\x01';
          }
        }
        else if (((DAT_803ddc98 != '\0') || (DAT_803ddc94 != 3)) ||
                ((DAT_803ddc92 != '\0' || (DAT_803ddc9a == '\0')))) {
          FUN_8025ce6c(0,3,0);
          DAT_803ddc98 = '\0';
          DAT_803ddc94 = 3;
          DAT_803ddc92 = '\0';
          DAT_803ddc9a = '\x01';
        }
        FUN_8025c754(7,0,0,7,0);
      }
      else {
        FUN_8025cce8(0,1,0,5);
        if ((*(ushort *)(iVar9 + 2) & 0x400) == 0) {
          if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\x01')) ||
             (DAT_803ddc9a == '\0')) {
            FUN_8025ce6c(1,3,1);
            DAT_803ddc98 = '\x01';
            DAT_803ddc94 = 3;
            DAT_803ddc92 = '\x01';
            DAT_803ddc9a = '\x01';
          }
        }
        else if (((DAT_803ddc98 != '\0') || (DAT_803ddc94 != 3)) ||
                ((DAT_803ddc92 != '\0' || (DAT_803ddc9a == '\0')))) {
          FUN_8025ce6c(0,3,0);
          DAT_803ddc98 = '\0';
          DAT_803ddc94 = 3;
          DAT_803ddc92 = '\0';
          DAT_803ddc9a = '\x01';
        }
        FUN_8025c754(4,0xc0,0,4,0xc0);
      }
    }
    else {
      FUN_8025cce8(1,4,5,5);
      if ((*(ushort *)(iVar9 + 2) & 0x400) == 0) {
        if ((*(ushort *)(iVar9 + 2) & 0x2000) == 0) {
          if (((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) ||
             ((DAT_803ddc92 != '\0' || (DAT_803ddc9a == '\0')))) {
            FUN_8025ce6c(1,3,0);
            DAT_803ddc98 = '\x01';
            DAT_803ddc94 = 3;
            DAT_803ddc92 = '\0';
            DAT_803ddc9a = '\x01';
          }
          FUN_8025c754(7,0,0,7,0);
        }
        else {
          uVar8 = 0;
          if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\x01')) ||
             (DAT_803ddc9a == '\0')) {
            FUN_8025ce6c(1,3,1);
            DAT_803ddc98 = '\x01';
            DAT_803ddc94 = 3;
            DAT_803ddc92 = '\x01';
            DAT_803ddc9a = '\x01';
          }
          uVar5 = FUN_8003bc6c();
          uVar6 = FUN_8003bc6c();
          FUN_8025c754(4,uVar6,0,4,uVar5);
        }
      }
      else {
        if (((DAT_803ddc98 != '\0') || (DAT_803ddc94 != 3)) ||
           ((DAT_803ddc92 != '\0' || (DAT_803ddc9a == '\0')))) {
          FUN_8025ce6c(0,3,0);
          DAT_803ddc98 = '\0';
          DAT_803ddc94 = 3;
          DAT_803ddc92 = '\0';
          DAT_803ddc9a = '\x01';
        }
        FUN_8025c754(7,0,0,7,0);
      }
    }
    if ((*(uint *)(iVar2 + 0x3c) & 0x400) != 0) {
      uVar8 = 0;
    }
    if ((DAT_803ddc91 != uVar8) || (DAT_803ddc99 == '\0')) {
      FUN_8025cee4(uVar8);
      DAT_803ddc91 = (byte)uVar8;
      DAT_803ddc99 = '\x01';
    }
  }
  else {
    (*pcVar4)(iVar1,piVar7,param_3);
  }
  FUN_80259288(0);
  if ((*(ushort *)(iVar9 + 2) & 0x100) == 0) {
    _local_90 = DAT_803ddc9c;
    FUN_8025ca38((double)FLOAT_803ddca4,(double)FLOAT_803ddca0,(double)FLOAT_803ddcb8,
                 (double)FLOAT_803ddcb4,4,&local_90);
  }
  else {
    _local_8c = local_80;
    dVar10 = (double)FLOAT_803dfb5c;
    FUN_8025ca38(dVar10,dVar10,dVar10,dVar10,0,&local_8c);
  }
  FUN_80286888();
  return;
}

