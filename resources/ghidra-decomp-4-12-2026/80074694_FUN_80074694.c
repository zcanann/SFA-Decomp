// Function: FUN_80074694
// Entry: 80074694
// Size: 2028 bytes

void FUN_80074694(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  uint *puVar3;
  uint uVar4;
  code *pcVar5;
  uint uVar6;
  uint uVar7;
  int *piVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  undefined4 local_d0;
  undefined4 local_cc;
  float local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  float afStack_b0 [12];
  float afStack_80 [11];
  float local_54;
  float afStack_50 [20];
  
  uVar11 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar11 >> 0x20);
  piVar8 = (int *)uVar11;
  local_c8 = DAT_802c26e8;
  local_c4 = DAT_802c26ec;
  local_c0 = DAT_802c26f0;
  local_bc = DAT_802c26f4;
  local_b8 = DAT_802c26f8;
  local_b4 = DAT_802c26fc;
  iVar9 = *piVar8;
  iVar2 = FUN_800284e8(iVar9,param_3);
  puVar3 = (uint *)FUN_8004c3cc(iVar2,0);
  uVar4 = FUN_8005383c(*puVar3);
  FUN_80247a7c((double)FLOAT_803dc314,(double)FLOAT_803dc314,(double)FLOAT_803dfb5c,afStack_80);
  local_54 = FLOAT_803dfb64;
  FUN_8025d8c4(afStack_80,0x55,0);
  FUN_80258674(0,0,1,0x1e,1,0x55);
  FUN_80258944(2);
  FUN_8025ca04(2);
  FUN_8025be54(2);
  FUN_8025bd1c(0,0,2);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_c8,'\0');
  FUN_8025b94c(0,0,0,7,1,0,0,0,0,0);
  FUN_8004c460(uVar4,0);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xc);
  FUN_8025c224(0,7,7,7,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025bd1c(1,0,2);
  FUN_8025bb48(1,0,0);
  FUN_8025b94c(1,1,0,7,1,0,0,1,0,0);
  FUN_80247a7c((double)FLOAT_803dc310,(double)FLOAT_803dc310,(double)FLOAT_803dfb64,afStack_b0);
  FUN_80247618(afStack_b0,(float *)&DAT_80397480,afStack_50);
  dVar10 = (double)(FLOAT_803dfb78 * (FLOAT_803dfb64 - FLOAT_803dc310));
  FUN_80247a48(dVar10,dVar10,(double)FLOAT_803dfb5c,afStack_b0);
  FUN_80247618(afStack_b0,afStack_50,afStack_50);
  FUN_8025d8c4(afStack_50,0x52,0);
  FUN_80258674(1,0,0,0,1,0x52);
  local_cc = CONCAT31(local_cc._0_3_,
                      (char)((uint)*(byte *)(iVar2 + 0xc) * (uint)*(byte *)(iVar1 + 0x37) >> 8));
  local_d0 = local_cc;
  FUN_8025c510(0,(byte *)&local_d0);
  FUN_8025c5f0(1,0x1c);
  FUN_8025c828(1,1,0,4);
  FUN_8025c1a4(1,0xf,10,8,0xf);
  FUN_8025c224(1,7,7,7,6);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  pcVar5 = (code *)FUN_80028588((int)piVar8);
  if (pcVar5 == (code *)0x0) {
    uVar4 = 1;
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
          uVar4 = 0;
          if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\x01')) ||
             (DAT_803ddc9a == '\0')) {
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
      uVar4 = 0;
    }
    if ((DAT_803ddc91 != uVar4) || (DAT_803ddc99 == '\0')) {
      FUN_8025cee4(uVar4);
      DAT_803ddc91 = (byte)uVar4;
      DAT_803ddc99 = '\x01';
    }
  }
  else {
    (*pcVar5)(iVar1,piVar8,param_3);
  }
  if ((*(uint *)(iVar2 + 0x3c) & 8) == 0) {
    FUN_80259288(0);
  }
  else {
    FUN_80259288(2);
  }
  FUN_80286888();
  return;
}

