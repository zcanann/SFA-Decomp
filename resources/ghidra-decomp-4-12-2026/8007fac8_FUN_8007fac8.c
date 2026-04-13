// Function: FUN_8007fac8
// Entry: 8007fac8
// Size: 1468 bytes

undefined4
FUN_8007fac8(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,char param_9
            ,undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 uVar8;
  undefined8 extraout_f1_02;
  uint local_88;
  int local_84;
  undefined auStack_80 [46];
  byte local_52;
  int local_50;
  ushort local_4c;
  ushort local_4a;
  int local_48;
  
  bVar2 = false;
  bVar3 = false;
  iVar4 = FUN_8007df88(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,'\0');
  if (iVar4 == 0) {
    bVar1 = false;
  }
  else {
    DAT_803ddcc0 = FUN_80023d8c(0xa000,-1);
    if (DAT_803ddcc0 == 0) {
      DAT_803dc360 = 8;
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
  }
  if (bVar1) {
    DAT_803dc360 = 0;
    iVar4 = FUN_80262b10(0,DAT_803ddcc0,&LAB_80080084);
    uVar8 = extraout_f1;
    if (iVar4 == -6) {
      iVar4 = FUN_8026218c(0);
      uVar8 = extraout_f1_00;
    }
    if ((iVar4 == 0) || (iVar4 == -0xd)) {
      iVar5 = FUN_8026218c(0);
      uVar8 = extraout_f1_01;
      iVar4 = FUN_80264b4c(0,&local_88);
      if (iVar4 == 0) {
        iVar4 = iVar5;
        if (DAT_803ddcd9 == '\0') {
          DAT_803ddccc = local_84;
          DAT_803ddcc8 = local_88;
        }
        else if (DAT_803ddccc == 0 && DAT_803ddcc8 == 0) {
          DAT_803ddccc = local_84;
          DAT_803ddcc8 = local_88;
        }
        else if (local_84 != DAT_803ddccc || local_88 != DAT_803ddcc8) {
          DAT_803dc360 = 0xb;
          iVar4 = -0x55;
        }
      }
    }
    if (iVar4 == 0) {
      iVar4 = FUN_80263710(0,DAT_803dc364,(int *)&DAT_80397560);
      if ((iVar4 == -4) && (param_9 == '\0')) {
        bVar2 = true;
        bVar3 = true;
      }
      uVar8 = extraout_f1_02;
      if (iVar4 == 0) {
        DAT_803ddcda = '\x01';
      }
    }
    if (((iVar4 == 0) && (iVar4 = FUN_80264864(0,DAT_80397564,(uint)auStack_80), iVar4 == 0)) &&
       ((local_50 == -1 || (local_48 == -1)))) {
      if (param_9 == '\0') {
        bVar3 = true;
      }
      else {
        iVar4 = -4;
      }
    }
    if (bVar3) {
      DAT_803ddcdc = FUN_80023d8c(0x4000,-1);
      if (DAT_803ddcdc == 0) {
        DAT_803dc360 = 8;
        FUN_80262bf4(0);
        FUN_800238c4(DAT_803ddcc0);
        DAT_803ddcc0 = 0;
        return 0;
      }
      uVar6 = 0;
      uVar7 = 0x4000;
      iVar5 = FUN_800033a8(DAT_803ddcdc,0,0x4000);
      FUN_8007f53c(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,uVar6,uVar7,
                   param_12,param_13,param_14,param_15,param_16);
    }
    if (bVar2) {
      iVar4 = FUN_80263c34(0,DAT_803dc364,0x6000,(int *)&DAT_80397560);
    }
    if (bVar3) {
      if (iVar4 == 0) {
        iVar4 = FUN_80264428((int *)&DAT_80397560,DAT_803ddcdc,0x4000,0);
        if (iVar4 == 0) {
          iVar4 = FUN_80264428((int *)&DAT_80397560,DAT_803ddcdc + 0x2000,0x2000,0x4000);
        }
        if (iVar4 == -5) {
          FUN_80264624(0,DAT_803dc364);
        }
        if ((bVar2) && (iVar4 == 0)) {
          iVar4 = FUN_80264864(0,DAT_80397564,(uint)auStack_80);
        }
        if (iVar4 == 0) {
          local_48 = 0;
          local_50 = 0x40;
          local_52 = local_52 & 0xf8 | 6;
          local_4c = local_4c & 0xff00 | 0x55;
          local_4a = local_4a & 0xfc00 | 0xff;
          iVar4 = FUN_80264b04(0,DAT_80397564,(int)auStack_80);
          if (iVar4 == 0) {
            DAT_803ddcd0 = *(undefined4 *)(DAT_803ddcdc + 0x3ff8);
            DAT_803ddcd4 = *(undefined4 *)(DAT_803ddcdc + 0x3ffc);
          }
        }
      }
      FUN_800238c4(DAT_803ddcdc);
    }
    if (iVar4 == -6) {
      DAT_803dc360 = 5;
    }
    else if (iVar4 < -6) {
      if (iVar4 == -0xd) {
        DAT_803dc360 = 6;
      }
      else if (((-0xe < iVar4) && (iVar4 < -7)) && (-10 < iVar4)) {
        DAT_803dc360 = 9;
      }
    }
    else {
      if (iVar4 == 0) {
        if (!bVar3) {
          return 2;
        }
        return 1;
      }
      if (iVar4 < 0) {
        if (iVar4 == -3) {
          if (DAT_803dc360 != 3) {
            DAT_803dc360 = 2;
          }
        }
        else if (iVar4 < -3) {
          if (iVar4 < -4) {
            DAT_803dc360 = 4;
          }
          else {
            DAT_803dc360 = 0xc;
          }
        }
      }
      else if (iVar4 < 2) {
        DAT_803dc360 = 1;
      }
    }
    if (DAT_803ddcda != '\0') {
      DAT_803ddcda = '\0';
      FUN_80263888((int *)&DAT_80397560);
    }
    FUN_80262bf4(0);
    FUN_800238c4(DAT_803ddcc0);
    DAT_803ddcc0 = 0;
  }
  return 0;
}

