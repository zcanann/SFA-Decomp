// Function: FUN_801bd0e8
// Entry: 801bd0e8
// Size: 1804 bytes

void FUN_801bd0e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,int param_14,int param_15,undefined4 param_16)

{
  byte bVar1;
  bool bVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 *puVar13;
  undefined8 uVar14;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  
  puVar3 = (undefined4 *)FUN_80286834();
  puVar13 = (undefined4 *)puVar3[0x2e];
  iVar12 = puVar3[0x13];
  FUN_8002bac4();
  iVar11 = puVar13[0x103];
  *(undefined2 *)((int)puVar13 + 0x402) = 0;
  uVar14 = (**(code **)(*DAT_803dd72c + 0x50))(0x1c,5,0);
  if (puVar3[0x3d] == 0) {
    puVar7 = (undefined4 *)&DAT_803ad63c;
    puVar8 = (undefined4 *)0x1;
    puVar9 = (undefined4 *)0x1;
    uVar14 = FUN_80114e4c(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                          param_11,(float *)&DAT_803ad63c,1,1,param_14,param_15,param_16);
    for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar10 = iVar10 + 1) {
      switch(*(undefined *)(param_11 + iVar10 + 0x81)) {
      case 1:
        (**(code **)(*DAT_803dd734 + 0xc))(puVar3,0x800,0,100,0);
        (**(code **)(*DAT_803dd734 + 0xc))(puVar3,0x800,0,100,0);
        (**(code **)(*DAT_803dd734 + 0xc))(puVar3,0x7ff,0,100,0);
        puVar7 = (undefined4 *)0x0;
        puVar8 = (undefined4 *)0x64;
        puVar9 = (undefined4 *)0x0;
        param_14 = *DAT_803dd734;
        (**(code **)(param_14 + 0xc))(puVar3,0x7ff);
        iVar4 = FUN_8002b660((int)puVar3);
        uVar14 = FUN_80028500(iVar4);
        FUN_8000a538((int *)0x27,1);
        break;
      case 2:
        *(undefined2 *)((int)puVar13 + 0x402) = 1;
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) & 0xf7;
        *(byte *)((int)puVar3 + 0xaf) = *(byte *)((int)puVar3 + 0xaf) | 0x80;
        puVar7 = (undefined4 *)0x0;
        puVar8 = (undefined4 *)*DAT_803dd72c;
        uVar14 = (*(code *)puVar8[0x14])(0x1c,0);
        break;
      case 6:
        DAT_803de800 = DAT_803de800 | 0x40004;
        break;
      case 7:
        DAT_803de800 = DAT_803de800 | 2;
        break;
      case 8:
        iVar11 = puVar13[0x103];
        *(byte *)(iVar11 + 0xb6) = *(byte *)(iVar11 + 0xb6) & 0x7f | 0x80;
        FUN_8000a538((int *)0xee,0);
        break;
      case 9:
        DAT_803de800 = DAT_803de800 | 0x40;
        break;
      case 10:
        DAT_803de800 = DAT_803de800 & 0xffffffbf;
        break;
      case 0xc:
        DAT_803de800 = DAT_803de800 & 0xffffff7f;
        break;
      case 0xd:
        DAT_803de800 = DAT_803de800 | 0x100;
        break;
      case 0xe:
        DAT_803de800 = DAT_803de800 & 0xfffffeff;
        break;
      case 0xf:
        DAT_803de800 = DAT_803de800 | 0x2001;
        break;
      case 0x10:
        DAT_803de800 = DAT_803de800 | 0x8021;
        break;
      case 0x11:
        *(undefined4 *)(iVar11 + 0xb0) = 10;
        FUN_800201ac(0x123,1);
        uVar14 = FUN_800201ac(0x17,1);
        FUN_8000a538((int *)0x27,0);
        FUN_8000a538((int *)0x36,0);
        FUN_8000a538((int *)0xee,0);
        break;
      case 0x12:
        puVar8 = (undefined4 *)0x3c;
        puVar9 = (undefined4 *)*DAT_803dd6d4;
        puVar7 = puVar3;
        uVar14 = (*(code *)puVar9[0x14])(0x49,4);
        break;
      case 0x13:
        puVar7 = (undefined4 *)0x1;
        puVar8 = (undefined4 *)*DAT_803dd72c;
        uVar14 = (*(code *)puVar8[0x14])(0x1c,2);
        break;
      case 0x14:
        puVar7 = (undefined4 *)0x0;
        puVar8 = (undefined4 *)*DAT_803dd72c;
        uVar14 = (*(code *)puVar8[0x14])(0x1c,2);
        break;
      case 0x15:
        FUN_8007d858();
        uVar14 = FUN_8004316c();
        puVar7 = (undefined4 *)0x1;
        FUN_80043604(0,0,1);
        FUN_8004832c(0x1c);
        uVar14 = FUN_80043938(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x1b);
        FUN_80043938(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        uVar14 = FUN_80041f34();
        break;
      case 0x16:
        uVar14 = FUN_8007d858();
        uVar5 = FUN_8004832c(0x13);
        FUN_80043658(uVar5,0);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        uVar14 = FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004832c(0x13);
        FUN_80044548(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        bVar2 = false;
        while (uVar6 = FUN_800431a4(), (uVar6 & 0xffefffff) != 0) {
          uVar14 = FUN_80014f6c();
          FUN_80020390();
          if (bVar2) {
            uVar14 = FUN_8004a9e4();
          }
          uVar14 = FUN_80048350(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          FUN_80015650(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          if (bVar2) {
            uVar14 = FUN_800235b0();
            FUN_80019c5c(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_8004a5b8('\x01');
          }
          if (DAT_803dd5d0 != '\0') {
            bVar2 = true;
          }
        }
        uVar14 = FUN_8004312c();
        break;
      case 0x17:
        DAT_803de800 = DAT_803de800 | 0x80000;
        break;
      case 0x18:
        DAT_803de800 = DAT_803de800 & 0xfff7ffff;
      }
    }
    if (*(short *)(puVar3 + 0x2d) != -1) {
      puVar7 = (undefined4 *)0x1;
      puVar8 = (undefined4 *)*DAT_803dd738;
      iVar11 = (*(code *)puVar8[0xc])(puVar3,puVar13);
      if (iVar11 == 0) goto LAB_801bd7dc;
      if (puVar3[0x32] != 0) {
        *(undefined4 *)(puVar3[0x32] + 0x30) = puVar3[0xc];
      }
      uVar14 = extraout_f1;
      if (((int)*(short *)((int)puVar13 + 0x3f6) != 0xffffffff) &&
         (uVar6 = FUN_80020078((int)*(short *)((int)puVar13 + 0x3f6)), uVar6 != 0)) {
        puVar7 = (undefined4 *)*DAT_803dd6d4;
        uVar14 = (*(code *)puVar7[0x16])(param_11,(int)*(short *)(iVar12 + 0x2c));
        *(undefined2 *)((int)puVar13 + 0x3f6) = 0xffff;
      }
      bVar1 = *(byte *)((int)puVar13 + 0x405);
      if (bVar1 == 1) {
        puVar8 = &DAT_803adc78;
        puVar9 = &DAT_803adc60;
        param_14 = 0;
        param_15 = *DAT_803dd738;
        puVar7 = puVar13;
        iVar11 = (**(code **)(param_15 + 0x34))(puVar3,param_11);
        uVar14 = extraout_f1_00;
        if (iVar11 != 0) {
          puVar7 = (undefined4 *)0x1;
          puVar8 = (undefined4 *)*DAT_803dd738;
          uVar14 = (*(code *)puVar8[0xb])((double)FLOAT_803e5908,puVar3,puVar13);
        }
      }
      else if ((bVar1 != 0) && (bVar1 < 3)) {
        *(undefined2 *)(param_11 + 0x6e) = 0;
        puVar7 = puVar13;
        puVar8 = puVar13;
        uVar14 = FUN_801bcd98(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,
                              param_11,(int)puVar13,(int)puVar13);
        if (*(char *)((int)puVar13 + 0x405) == '\x01') {
          *(undefined2 *)(puVar13 + 0x9c) = 0;
          param_2 = (double)FLOAT_803e58dc;
          puVar7 = &DAT_803adc78;
          puVar8 = &DAT_803adc60;
          puVar9 = (undefined4 *)*DAT_803dd70c;
          uVar14 = (*(code *)puVar9[2])(puVar3,puVar13);
          *(undefined *)(param_11 + 0x56) = 0;
        }
      }
    }
    FUN_801bc0f8(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,puVar13,
                 puVar7,puVar8,puVar9,param_14,param_15,param_16);
    if (*(short *)(puVar3 + 0x2d) == -1) {
      *(ushort *)(puVar13 + 0x100) = *(ushort *)(puVar13 + 0x100) | 2;
    }
  }
LAB_801bd7dc:
  FUN_80286880();
  return;
}

