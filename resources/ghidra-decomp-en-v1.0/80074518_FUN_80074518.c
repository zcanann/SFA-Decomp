// Function: FUN_80074518
// Entry: 80074518
// Size: 2028 bytes

void FUN_80074518(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  code *pcVar5;
  undefined4 uVar6;
  int *piVar7;
  char cVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  uint local_d0;
  uint local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined auStack176 [48];
  undefined auStack128 [44];
  float local_54;
  undefined auStack80 [80];
  
  uVar11 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar11 >> 0x20);
  piVar7 = (int *)uVar11;
  local_c8 = DAT_802c1f68;
  local_c4 = DAT_802c1f6c;
  local_c0 = DAT_802c1f70;
  local_bc = DAT_802c1f74;
  local_b8 = DAT_802c1f78;
  local_b4 = DAT_802c1f7c;
  iVar9 = *piVar7;
  iVar2 = FUN_80028424(iVar9,param_3);
  puVar3 = (undefined4 *)FUN_8004c250(iVar2,0);
  uVar4 = FUN_800536c0(*puVar3);
  FUN_80247318((double)FLOAT_803db6b4,(double)FLOAT_803db6b4,(double)FLOAT_803deedc,auStack128);
  local_54 = FLOAT_803deee4;
  FUN_8025d160(auStack128,0x55,0);
  FUN_80257f10(0,0,1,0x1e,1,0x55);
  FUN_802581e0(2);
  FUN_8025c2a0(2);
  FUN_8025b6f0(2);
  FUN_8025b5b8(0,0,2);
  FUN_8025b3e4(0,0,0);
  FUN_8025b284(1,&local_c8,0);
  FUN_8025b1e8(0,0,0,7,1,0,0,0,0,0);
  FUN_8004c2e4(uVar4,0);
  FUN_8025c0c4(0,0,0,0xff);
  FUN_8025ba40(0,0xf,0xf,0xf,0xc);
  FUN_8025bac0(0,7,7,7,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  FUN_8025b5b8(1,0,2);
  FUN_8025b3e4(1,0,0);
  FUN_8025b1e8(1,1,0,7,1,0,0,1,0,0);
  FUN_80247318((double)FLOAT_803db6b0,(double)FLOAT_803db6b0,(double)FLOAT_803deee4,auStack176);
  FUN_80246eb4(auStack176,&DAT_80396820,auStack80);
  dVar10 = (double)(FLOAT_803deef8 * (FLOAT_803deee4 - FLOAT_803db6b0));
  FUN_802472e4(dVar10,dVar10,(double)FLOAT_803deedc,auStack176);
  FUN_80246eb4(auStack176,auStack80,auStack80);
  FUN_8025d160(auStack80,0x52,0);
  FUN_80257f10(1,0,0,0,1,0x52);
  local_cc = local_cc & 0xffffff00 |
             (uint)*(byte *)(iVar2 + 0xc) * (uint)*(byte *)(iVar1 + 0x37) >> 8;
  local_d0 = local_cc;
  FUN_8025bdac(0,&local_d0);
  FUN_8025be8c(1,0x1c);
  FUN_8025c0c4(1,1,0,4);
  FUN_8025ba40(1,0xf,10,8,0xf);
  FUN_8025bac0(1,7,7,7,6);
  FUN_8025bef8(1,0,0);
  FUN_8025bb44(1,0,0,0,1,0);
  FUN_8025bc04(1,0,0,0,1,0);
  pcVar5 = (code *)FUN_800284c4(piVar7);
  if (pcVar5 == (code *)0x0) {
    cVar8 = '\x01';
    if (((*(char *)(iVar1 + 0x37) == -1) && ((*(uint *)(iVar2 + 0x3c) & 0x40000000) == 0)) &&
       (*(char *)(iVar2 + 0xc) == -1)) {
      if ((*(uint *)(iVar2 + 0x3c) & 0x400) == 0) {
        FUN_8025c584(0,1,0,5);
        if ((*(ushort *)(iVar9 + 2) & 0x400) == 0) {
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
        if ((*(ushort *)(iVar9 + 2) & 0x400) == 0) {
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
      if ((*(ushort *)(iVar9 + 2) & 0x400) == 0) {
        if ((*(ushort *)(iVar9 + 2) & 0x2000) == 0) {
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
          cVar8 = '\0';
          if ((((DAT_803dd018 != '\x01') || (DAT_803dd014 != 3)) || (DAT_803dd012 != '\x01')) ||
             (DAT_803dd01a == '\0')) {
            FUN_8025c708(1,3,1);
            DAT_803dd018 = '\x01';
            DAT_803dd014 = 3;
            DAT_803dd012 = '\x01';
            DAT_803dd01a = '\x01';
          }
          uVar4 = FUN_8003bb74();
          uVar6 = FUN_8003bb74();
          FUN_8025bff0(4,uVar6,0,4,uVar4);
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
      cVar8 = '\0';
    }
    if ((DAT_803dd011 != cVar8) || (DAT_803dd019 == '\0')) {
      FUN_8025c780(cVar8);
      DAT_803dd019 = '\x01';
      DAT_803dd011 = cVar8;
    }
  }
  else {
    (*pcVar5)(iVar1,piVar7,param_3);
  }
  if ((*(uint *)(iVar2 + 0x3c) & 8) == 0) {
    FUN_80258b24(0);
  }
  else {
    FUN_80258b24(2);
  }
  FUN_80286124(1);
  return;
}

