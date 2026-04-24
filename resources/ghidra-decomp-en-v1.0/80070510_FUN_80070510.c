// Function: FUN_80070510
// Entry: 80070510
// Size: 2500 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80070510(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  int iVar6;
  char cVar9;
  code *pcVar7;
  undefined4 uVar8;
  int *piVar10;
  int iVar11;
  double dVar12;
  undefined8 uVar13;
  undefined auStack112 [4];
  undefined4 local_6c;
  undefined4 local_68;
  undefined auStack100 [4];
  float local_60;
  undefined auStack92 [28];
  float local_40;
  
  uVar13 = FUN_802860d4();
  iVar2 = (int)((ulonglong)uVar13 >> 0x20);
  piVar10 = (int *)uVar13;
  iVar11 = *piVar10;
  iVar3 = FUN_80028424(iVar11,param_3);
  puVar4 = (undefined4 *)FUN_8004c250(iVar3,0);
  uVar5 = FUN_800536c0(*puVar4);
  FUN_8004c2e4(uVar5,0);
  FUN_8006c6f0(1);
  iVar6 = FUN_800536c0(*(undefined4 *)(iVar3 + 0x34));
  FUN_8025a310(iVar6 + 0x20,iVar6 + 0x60,*(undefined2 *)(iVar6 + 10),*(undefined2 *)(iVar6 + 0xc),
               *(undefined *)(iVar6 + 0x16),1,1,
               0 < (int)((uint)*(byte *)(iVar6 + 0x1d) - (uint)*(byte *)(iVar6 + 0x1c)));
  FUN_8004c2e4(iVar6,2);
  FUN_8025d160(&DAT_80396850,0x52,0);
  FUN_80257f10(0,0,0,0,0,0x52);
  FUN_8025d160(&DAT_80396820,0x55,0);
  FUN_80257f10(1,0,0,0,0,0x55);
  FUN_8006cabc(&local_60,auStack100);
  dVar12 = (double)FLOAT_803deee4;
  FUN_80247318(dVar12,dVar12,dVar12,auStack92);
  local_40 = -local_60;
  FUN_8025d160(auStack92,0x21,1);
  FUN_80257f10(2,1,4,0x21,0,0x7d);
  FUN_80257f10(3,1,4,0x21,0,0x7d);
  cVar9 = FUN_8004c248();
  if (cVar9 == '\0') {
    (**(code **)(*DAT_803dca58 + 0x40))
              (&DAT_803db6f4,0x803db6f5,0x803db6f6,auStack112,auStack112,auStack112);
    bVar1 = (byte)((int)((_DAT_803db6f4 & 0xff0000) >> 0x10) >> 3);
    _DAT_803db6f4 =
         (ushort)((uint)(((int)(_DAT_803db6f4 >> 0x18) >> 3) << 0x18) >> 0x10) | (ushort)bVar1;
    _DAT_803db6f4 =
         CONCAT31(CONCAT21(_DAT_803db6f4,
                           (char)((int)((CONCAT12(bVar1,(short)_DAT_803db6f4) & 0xff00) >> 8) >> 3))
                  ,DAT_803db678);
  }
  else {
    _DAT_803db6f4 =
         CONCAT31(CONCAT21(CONCAT11(DAT_803dd01c._0_1_,DAT_803dd01c._1_1_),DAT_803dd01c._2_1_),0x80)
    ;
  }
  local_68 = _DAT_803db6f4;
  FUN_8025bcc4(3,&local_68);
  local_6c = DAT_803db6f8;
  FUN_8025bdac(0,&local_6c);
  FUN_8025be20(1,0xc);
  FUN_8025b5b8(0,2,2);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&DAT_8030eaa0,0xffffffff);
  FUN_8025b284(2,&DAT_8030eaa0,0xfffffffe);
  FUN_8025b1e8(0,0,0,7,1,0,0,0,0,0);
  FUN_8025b1e8(1,0,0,7,2,0,0,0,0,0);
  FUN_8025c0c4(0,0,1,0xff);
  FUN_8025ba40(0,6,0xf,0xf,8);
  FUN_8025bac0(0,7,7,7,7);
  FUN_8025bef8(0,0,0);
  cVar9 = FUN_8004c248();
  if (cVar9 == '\0') {
    FUN_8025bb44(0,0,0,0,1,0);
  }
  else {
    FUN_8025bb44(0,0,0,3,1,0);
  }
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025c0c4(1,1,1,0xff);
  FUN_8025ba40(1,0,8,0xe,0xf);
  FUN_8025bac0(1,7,7,7,7);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  FUN_8025b71c(2);
  FUN_8025c0c4(2,3,0,4);
  FUN_8025ba40(2,0,8,9,0xf);
  FUN_8025bac0(2,7,7,7,5);
  FUN_8025bef8(2,0,0);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bc04(2,0,0,0,1,0);
  FUN_80259ea4(0,0,0,1,0,0,2);
  FUN_80259ea4(2,0,0,1,0,0,2);
  FUN_8025b6f0(1);
  FUN_80259e58(1);
  FUN_802581e0(4);
  FUN_8025c2a0(3);
  pcVar7 = (code *)FUN_800284c4(piVar10);
  if (pcVar7 == (code *)0x0) {
    cVar9 = '\x01';
    if (((*(char *)(iVar2 + 0x37) == -1) && ((*(uint *)(iVar3 + 0x3c) & 0x40000000) == 0)) &&
       (*(char *)(iVar3 + 0xc) == -1)) {
      if ((*(uint *)(iVar3 + 0x3c) & 0x400) == 0) {
        FUN_8025c584(0,1,0,5);
        if ((*(ushort *)(iVar11 + 2) & 0x400) == 0) {
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
        if ((*(ushort *)(iVar11 + 2) & 0x400) == 0) {
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
      if ((*(ushort *)(iVar11 + 2) & 0x400) == 0) {
        if ((*(ushort *)(iVar11 + 2) & 0x2000) == 0) {
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
          cVar9 = '\0';
          if (((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) ||
             ((DAT_803dd012 != '\x01' || (DAT_803dd01a == '\0')))) {
            FUN_8025c708(1,3,1);
            DAT_803dd018 = '\x01';
            DAT_803dd014 = 3;
            DAT_803dd012 = '\x01';
            DAT_803dd01a = '\x01';
          }
          uVar5 = FUN_8003bb74();
          uVar8 = FUN_8003bb74();
          FUN_8025bff0(4,uVar8,0,4,uVar5);
        }
      }
      else {
        if ((((DAT_803dd018 != '\0') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\0')) ||
           (DAT_803dd01a == '\0')) {
          FUN_8025c708(0,3,0);
          DAT_803dd018 = '\0';
          DAT_803dd014 = 3;
          DAT_803dd012 = '\0';
          DAT_803dd01a = '\x01';
        }
        FUN_8025bff0(7,0,0,7,0);
      }
    }
    if ((*(uint *)(iVar3 + 0x3c) & 0x400) != 0) {
      cVar9 = '\0';
    }
    if ((DAT_803dd011 != cVar9) || (DAT_803dd019 == '\0')) {
      FUN_8025c780(cVar9);
      DAT_803dd019 = '\x01';
      DAT_803dd011 = cVar9;
    }
  }
  else {
    (*pcVar7)(iVar2,piVar10,param_3);
  }
  if ((*(uint *)(iVar3 + 0x3c) & 8) == 0) {
    FUN_80258b24(0);
  }
  else {
    FUN_80258b24(2);
  }
  FUN_80286120(1);
  return;
}

