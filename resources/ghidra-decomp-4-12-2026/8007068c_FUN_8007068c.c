// Function: FUN_8007068c
// Entry: 8007068c
// Size: 2500 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8007068c(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  uint *puVar3;
  uint uVar4;
  char cVar8;
  code *pcVar5;
  uint uVar6;
  uint uVar7;
  int *piVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  undefined auStack_70 [4];
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 uStack_64;
  float local_60;
  float afStack_5c [7];
  float local_40;
  
  uVar12 = FUN_80286838();
  iVar1 = (int)((ulonglong)uVar12 >> 0x20);
  piVar9 = (int *)uVar12;
  iVar10 = *piVar9;
  iVar2 = FUN_800284e8(iVar10,param_3);
  puVar3 = (uint *)FUN_8004c3cc(iVar2,0);
  uVar4 = FUN_8005383c(*puVar3);
  FUN_8004c460(uVar4,0);
  FUN_8006c86c(1);
  uVar4 = FUN_8005383c(*(uint *)(iVar2 + 0x34));
  FUN_8025aa74((uint *)(uVar4 + 0x20),uVar4 + 0x60,(uint)*(ushort *)(uVar4 + 10),
               (uint)*(ushort *)(uVar4 + 0xc),(uint)*(byte *)(uVar4 + 0x16),1,1,
               0 < (int)((uint)*(byte *)(uVar4 + 0x1d) - (uint)*(byte *)(uVar4 + 0x1c)));
  FUN_8004c460(uVar4,2);
  FUN_8025d8c4((float *)&DAT_803974b0,0x52,0);
  FUN_80258674(0,0,0,0,0,0x52);
  FUN_8025d8c4((float *)&DAT_80397480,0x55,0);
  FUN_80258674(1,0,0,0,0,0x55);
  FUN_8006cc38(&local_60,&uStack_64);
  dVar11 = (double)FLOAT_803dfb64;
  FUN_80247a7c(dVar11,dVar11,dVar11,afStack_5c);
  local_40 = -local_60;
  FUN_8025d8c4(afStack_5c,0x21,1);
  FUN_80258674(2,1,4,0x21,0,0x7d);
  FUN_80258674(3,1,4,0x21,0,0x7d);
  cVar8 = FUN_8004c3c4();
  if (cVar8 == '\0') {
    (**(code **)(*DAT_803dd6d8 + 0x40))
              (&DAT_803dc354,0x803dc355,0x803dc356,auStack_70,auStack_70,auStack_70);
    _DAT_803dc354 =
         CONCAT31(CONCAT21(CONCAT11((char)((int)(_DAT_803dc354 >> 0x18) >> 3),
                                    (char)((int)(_DAT_803dc354 >> 0x10 & 0xff) >> 3)),
                           (char)((int)(_DAT_803dc354 >> 8 & 0xff) >> 3)),DAT_803dc2d8);
  }
  else {
    _DAT_803dc354 =
         CONCAT31(CONCAT21(CONCAT11(DAT_803ddc9c._0_1_,DAT_803ddc9c._1_1_),DAT_803ddc9c._2_1_),0x80)
    ;
  }
  local_68 = _DAT_803dc354;
  FUN_8025c428(3,(byte *)&local_68);
  local_6c = DAT_803dc358;
  FUN_8025c510(0,(byte *)&local_6c);
  FUN_8025c584(1,0xc);
  FUN_8025bd1c(0,2,2);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,(float *)&DAT_8030f660,-1);
  FUN_8025b9e8(2,(float *)&DAT_8030f660,-2);
  FUN_8025b94c(0,0,0,7,1,0,0,0,0,0);
  FUN_8025b94c(1,0,0,7,2,0,0,0,0,0);
  FUN_8025c828(0,0,1,0xff);
  FUN_8025c1a4(0,6,0xf,0xf,8);
  FUN_8025c224(0,7,7,7,7);
  FUN_8025c65c(0,0,0);
  cVar8 = FUN_8004c3c4();
  if (cVar8 == '\0') {
    FUN_8025c2a8(0,0,0,0,1,0);
  }
  else {
    FUN_8025c2a8(0,0,0,3,1,0);
  }
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025c828(1,1,1,0xff);
  FUN_8025c1a4(1,0,8,0xe,0xf);
  FUN_8025c224(1,7,7,7,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  FUN_8025be80(2);
  FUN_8025c828(2,3,0,4);
  FUN_8025c1a4(2,0,8,9,0xf);
  FUN_8025c224(2,7,7,7,5);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,0,1,0);
  FUN_8025a608(0,0,0,1,0,0,2);
  FUN_8025a608(2,0,0,1,0,0,2);
  FUN_8025be54(1);
  FUN_8025a5bc(1);
  FUN_80258944(4);
  FUN_8025ca04(3);
  pcVar5 = (code *)FUN_80028588((int)piVar9);
  if (pcVar5 == (code *)0x0) {
    uVar4 = 1;
    if (((*(char *)(iVar1 + 0x37) == -1) && ((*(uint *)(iVar2 + 0x3c) & 0x40000000) == 0)) &&
       (*(char *)(iVar2 + 0xc) == -1)) {
      if ((*(uint *)(iVar2 + 0x3c) & 0x400) == 0) {
        FUN_8025cce8(0,1,0,5);
        if ((*(ushort *)(iVar10 + 2) & 0x400) == 0) {
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
        if ((*(ushort *)(iVar10 + 2) & 0x400) == 0) {
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
      if ((*(ushort *)(iVar10 + 2) & 0x400) == 0) {
        if ((*(ushort *)(iVar10 + 2) & 0x2000) == 0) {
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
          uVar4 = 0;
          if (((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) ||
             ((DAT_803ddc92 != '\x01' || (DAT_803ddc9a == '\0')))) {
            FUN_8025ce6c(1,3,1);
            DAT_803ddc98 = '\x01';
            DAT_803ddc94 = 3;
            DAT_803ddc92 = '\x01';
            DAT_803ddc9a = '\x01';
          }
          uVar6 = FUN_8003bc6c();
          uVar7 = FUN_8003bc6c();
          FUN_8025c754(4,uVar7,0,4,uVar6);
        }
      }
      else {
        if ((((DAT_803ddc98 != '\0') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\0')) ||
           (DAT_803ddc9a == '\0')) {
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
      uVar4 = 0;
    }
    if ((DAT_803ddc91 != uVar4) || (DAT_803ddc99 == '\0')) {
      FUN_8025cee4(uVar4);
      DAT_803ddc91 = (byte)uVar4;
      DAT_803ddc99 = '\x01';
    }
  }
  else {
    (*pcVar5)(iVar1,piVar9,param_3);
  }
  if ((*(uint *)(iVar2 + 0x3c) & 8) == 0) {
    FUN_80259288(0);
  }
  else {
    FUN_80259288(2);
  }
  FUN_80286884();
  return;
}

