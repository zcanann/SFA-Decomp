// Function: FUN_80072dfc
// Entry: 80072dfc
// Size: 2160 bytes

void FUN_80072dfc(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  code *pcVar4;
  undefined4 uVar5;
  int *piVar6;
  char cVar7;
  int iVar8;
  double dVar9;
  undefined8 uVar10;
  undefined4 local_90;
  uint local_8c;
  undefined4 local_88;
  uint local_84;
  uint local_80;
  undefined auStack124 [48];
  undefined auStack76 [12];
  float local_40;
  float local_30;
  float local_20;
  
  uVar10 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  piVar6 = (int *)uVar10;
  iVar8 = *piVar6;
  iVar2 = FUN_80028424(iVar8,param_3);
  uVar3 = FUN_8006c744();
  FUN_8006c6f0(0);
  FUN_8004c2e4(uVar3,1);
  FUN_8006c6a4(2);
  FUN_8025d160(&DAT_80396820,0x55,0);
  FUN_80257f10(1,0,0,0,0,0x55);
  if ((iVar8 == 0) || (*(short *)(iVar8 + 0xe6) != 0)) {
    FUN_80247318((double)FLOAT_803db6b8,(double)FLOAT_803db6b8,(double)FLOAT_803deedc,auStack76);
    local_20 = FLOAT_803deee4;
    FUN_802472e4((double)FLOAT_803deef8,(double)FLOAT_803deef8,(double)FLOAT_803deedc,auStack124);
    FUN_80246eb4(auStack124,auStack76,auStack76);
  }
  else {
    dVar9 = (double)FLOAT_803deedc;
    FUN_80247318(dVar9,dVar9,dVar9,auStack76);
    local_40 = FLOAT_803deef8;
    local_30 = FLOAT_803deef8;
    local_20 = FLOAT_803deee4;
  }
  FUN_8025d160(auStack76,0x52,0);
  FUN_80257f10(0,0,1,0x1e,1,0x52);
  FUN_80247318((double)FLOAT_803db6c0,(double)FLOAT_803db6c0,(double)FLOAT_803deedc,auStack76);
  local_20 = FLOAT_803deee4;
  FUN_8025d160(auStack76,0x4f,0);
  FUN_80257f10(2,0,4,0x3c,0,0x4f);
  FUN_8025b5b8(0,1,1);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&DAT_8030ea58,0xffffffff);
  FUN_8025b1e8(0,0,0,7,1,0,0,0,0,0);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025ba40(0,0xf,0xf,0xf,8);
  FUN_8025bac0(0,7,7,7,6);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025b71c(1);
  FUN_8025c0c4(1,2,2,0xff);
  FUN_8025ba40(1,0,8,0xe,0xf);
  FUN_8025bac0(1,7,7,7,0);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  FUN_8025b6f0(1);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259ea4(5,0,0,0,0,0,2);
  FUN_80259e58(0);
  FUN_802581e0(3);
  FUN_8025c2a0(2);
  local_80 = local_80 & 0xffffff00 |
             (uint)*(byte *)(iVar2 + 0xc) * (uint)*(byte *)(iVar1 + 0x37) >> 8;
  local_84 = local_80;
  FUN_8025bdac(0,&local_84);
  FUN_8025be8c(0,0x1c);
  local_88 = DAT_803db6bc;
  FUN_8025bdac(1,&local_88);
  FUN_8025be20(1,0xd);
  pcVar4 = (code *)FUN_800284c4(piVar6);
  if (pcVar4 == (code *)0x0) {
    cVar7 = '\x01';
    if (((*(char *)(iVar1 + 0x37) == -1) && ((*(uint *)(iVar2 + 0x3c) & 0x40000000) == 0)) &&
       (*(char *)(iVar2 + 0xc) == -1)) {
      if ((*(uint *)(iVar2 + 0x3c) & 0x400) == 0) {
        FUN_8025c584(0,1,0,5);
        if ((*(ushort *)(iVar8 + 2) & 0x400) == 0) {
          if (((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) ||
             ((DAT_803dd012 != '\x01' || (DAT_803dd01a == '\0')))) {
            FUN_8025c708(1,3,1);
            DAT_803dd018 = '\x01';
            DAT_803dd014 = 3;
            DAT_803dd012 = '\x01';
            DAT_803dd01a = '\x01';
          }
        }
        else if (((DAT_803dd018 != '\0') || (DAT_803dd014 != 3)) ||
                ((DAT_803dd012 != '\0' || (DAT_803dd01a == '\0')))) {
          FUN_8025c708(0,3,0);
          DAT_803dd018 = '\0';
          DAT_803dd014 = 3;
          DAT_803dd012 = '\0';
          DAT_803dd01a = '\x01';
        }
        FUN_8025bff0(7,0,0,7,0);
      }
      else {
        FUN_8025c584(0,1,0,5);
        if ((*(ushort *)(iVar8 + 2) & 0x400) == 0) {
          if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\x01')) ||
             (DAT_803dd01a == '\0')) {
            FUN_8025c708(1,3,1);
            DAT_803dd018 = '\x01';
            DAT_803dd014 = 3;
            DAT_803dd012 = '\x01';
            DAT_803dd01a = '\x01';
          }
        }
        else if (((DAT_803dd018 != '\0') || (DAT_803dd014 != 3)) ||
                ((DAT_803dd012 != '\0' || (DAT_803dd01a == '\0')))) {
          FUN_8025c708(0,3,0);
          DAT_803dd018 = '\0';
          DAT_803dd014 = 3;
          DAT_803dd012 = '\0';
          DAT_803dd01a = '\x01';
        }
        FUN_8025bff0(4,0xc0,0,4,0xc0);
      }
    }
    else {
      FUN_8025c584(1,4,5,5);
      if ((*(ushort *)(iVar8 + 2) & 0x400) == 0) {
        if ((*(ushort *)(iVar8 + 2) & 0x2000) == 0) {
          if (((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) ||
             ((DAT_803dd012 != '\0' || (DAT_803dd01a == '\0')))) {
            FUN_8025c708(1,3,0);
            DAT_803dd018 = '\x01';
            DAT_803dd014 = 3;
            DAT_803dd012 = '\0';
            DAT_803dd01a = '\x01';
          }
          FUN_8025bff0(7,0,0,7,0);
        }
        else {
          cVar7 = '\0';
          if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\x01')) ||
             (DAT_803dd01a == '\0')) {
            FUN_8025c708(1,3,1);
            DAT_803dd018 = '\x01';
            DAT_803dd014 = 3;
            DAT_803dd012 = '\x01';
            DAT_803dd01a = '\x01';
          }
          uVar3 = FUN_8003bb74();
          uVar5 = FUN_8003bb74();
          FUN_8025bff0(4,uVar5,0,4,uVar3);
        }
      }
      else {
        if (((DAT_803dd018 != '\0') || (DAT_803dd014 != 3)) ||
           ((DAT_803dd012 != '\0' || (DAT_803dd01a == '\0')))) {
          FUN_8025c708(0,3,0);
          DAT_803dd018 = '\0';
          DAT_803dd014 = 3;
          DAT_803dd012 = '\0';
          DAT_803dd01a = '\x01';
        }
        FUN_8025bff0(7,0,0,7,0);
      }
    }
    if ((*(uint *)(iVar2 + 0x3c) & 0x400) != 0) {
      cVar7 = '\0';
    }
    if ((DAT_803dd011 != cVar7) || (DAT_803dd019 == '\0')) {
      FUN_8025c780(cVar7);
      DAT_803dd019 = '\x01';
      DAT_803dd011 = cVar7;
    }
  }
  else {
    (*pcVar4)(iVar1,piVar6,param_3);
  }
  FUN_80258b24(0);
  if ((*(ushort *)(iVar8 + 2) & 0x100) == 0) {
    local_90 = DAT_803dd01c;
    FUN_8025c2d4((double)FLOAT_803dd024,(double)FLOAT_803dd020,(double)FLOAT_803dd038,
                 (double)FLOAT_803dd034,4,&local_90);
  }
  else {
    local_8c = local_80;
    dVar9 = (double)FLOAT_803deedc;
    FUN_8025c2d4(dVar9,dVar9,dVar9,dVar9,0,&local_8c);
  }
  FUN_80286124(1);
  return;
}

