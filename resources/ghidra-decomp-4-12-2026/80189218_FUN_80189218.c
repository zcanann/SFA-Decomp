// Function: FUN_80189218
// Entry: 80189218
// Size: 1552 bytes

undefined4
FUN_80189218(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,int param_12,undefined4 param_13,undefined4 param_14,undefined4 param_15,
            undefined4 param_16)

{
  undefined4 uVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 extraout_f1_03;
  undefined8 uVar8;
  
  iVar6 = *(int *)(param_9 + 0x4c);
  iVar5 = *(int *)(param_9 + 0xb8);
  iVar7 = 0;
  iVar4 = param_11;
  do {
    if ((int)(uint)*(byte *)(param_11 + 0x8b) <= iVar7) {
      return 0;
    }
    switch(*(undefined *)(param_11 + iVar7 + 0x81)) {
    case 2:
    case 0x65:
      iVar4 = *(int *)(iVar6 + 0x14);
      if (iVar4 == 0x49f5a) {
        FUN_80043070(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x26);
        iVar4 = 1;
        FUN_80043604(0,0,1);
        uVar1 = FUN_8004832c(0x26);
        FUN_80043658(uVar1,0);
        uVar1 = FUN_8004832c(0xb);
        FUN_80043658(uVar1,1);
      }
      else if (iVar4 < 0x49f5a) {
        if (iVar4 == 0x451b9) {
          cVar2 = (**(code **)(*DAT_803dd72c + 0x40))(0xd);
          param_1 = extraout_f1;
          if (cVar2 == '\x02') {
            FUN_80043070(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
            iVar4 = 1;
            FUN_80043604(0,0,1);
            uVar1 = FUN_8004832c(0xb);
            FUN_80043658(uVar1,0);
          }
          else {
            FUN_80043070(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
            iVar4 = 1;
            FUN_80043604(0,0,1);
            uVar1 = FUN_8004832c(0x29);
            FUN_80043658(uVar1,0);
          }
        }
        else {
          if ((0x451b8 < iVar4) || (iVar4 != 0x43775)) goto LAB_801893dc;
          FUN_80043070(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
          iVar4 = 1;
          FUN_80043604(0,0,1);
          uVar1 = FUN_8004832c(0x29);
          FUN_80043658(uVar1,0);
        }
      }
      else if (iVar4 == 0x4cd65) {
        FUN_80043070(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x41);
        iVar4 = 1;
        FUN_80043604(0,0,1);
        uVar1 = FUN_8004832c(0x41);
        FUN_80043658(uVar1,0);
        uVar1 = FUN_8004832c(0xb);
        FUN_80043658(uVar1,1);
      }
      else {
LAB_801893dc:
        FUN_80043070(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
        iVar4 = 1;
        FUN_80043604(0,0,1);
        uVar1 = FUN_8004832c(0x29);
        FUN_80043658(uVar1,0);
      }
      break;
    case 3:
    case 100:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x49f5a) {
        iVar4 = 0;
        param_12 = *DAT_803dd72c;
        param_1 = (**(code **)(param_12 + 0x50))(0xb,4);
      }
      else if (iVar3 < 0x49f5a) {
        if (iVar3 == 0x451b9) {
          cVar2 = (**(code **)(*DAT_803dd72c + 0x40))(0xd);
          param_1 = extraout_f1_00;
          if (cVar2 == '\x02') {
            uVar8 = extraout_f1_00;
            FUN_80043604(0,0,1);
            FUN_8004832c(0xd);
            FUN_80043938(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            (**(code **)(*DAT_803dd72c + 0x50))(0xd,10,0);
            (**(code **)(*DAT_803dd72c + 0x50))(0xd,0xb,0);
            iVar4 = 0;
            param_12 = *DAT_803dd72c;
            param_1 = (**(code **)(param_12 + 0x50))(0xd,0xe);
          }
        }
        else if ((iVar3 < 0x451b9) && (iVar3 == 0x43775)) {
          iVar4 = 1;
          FUN_80043604(0,0,1);
          FUN_8004832c(7);
          param_1 = FUN_80043938(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
      }
      else if (iVar3 == 0x4cd65) {
        iVar4 = 1;
        FUN_80043604(0,0,1);
        FUN_8004832c(0xb);
        param_1 = FUN_80043938(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      break;
    case 5:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x451b9) {
        cVar2 = (**(code **)(*DAT_803dd72c + 0x40))(0xd);
        param_1 = extraout_f1_01;
        if (cVar2 == '\x02') {
          param_1 = FUN_8004316c();
        }
      }
      else if (iVar3 < 0x451b9) {
        if (iVar3 == 0x43775) {
LAB_801895a4:
          param_1 = FUN_8004316c();
        }
      }
      else if (iVar3 == 0x49f5a) goto LAB_801895a4;
      break;
    case 6:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x451b9) {
        cVar2 = (**(code **)(*DAT_803dd72c + 0x40))(0xd);
        param_1 = extraout_f1_02;
        if (cVar2 == '\x02') {
          param_1 = FUN_8004312c();
        }
      }
      else if (iVar3 < 0x451b9) {
        if (iVar3 == 0x43775) {
LAB_80189614:
          param_1 = FUN_8004312c();
        }
      }
      else if (iVar3 == 0x49f5a) goto LAB_80189614;
      break;
    case 7:
    case 0x66:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x49f5a) {
        param_1 = FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,
                               '\0',iVar4,param_12,param_13,param_14,param_15,param_16);
      }
      else if (iVar3 < 0x49f5a) {
        if ((iVar3 == 0x451b9) &&
           (cVar2 = (**(code **)(*DAT_803dd72c + 0x40))(0xd), param_1 = extraout_f1_03,
           cVar2 == '\x02')) {
          iVar4 = *DAT_803dd72c;
          uVar8 = (**(code **)(iVar4 + 0x44))(0xb,5);
          param_1 = FUN_80055464(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x4e,
                                 '\0',iVar4,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else if (iVar3 == 0x4cd65) {
        FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7f,'\0',iVar4
                     ,param_12,param_13,param_14,param_15,param_16);
        iVar4 = *DAT_803dd72c;
        param_1 = (**(code **)(iVar4 + 0x44))(0x41,2);
      }
      break;
    case 10:
      *(undefined *)(iVar5 + 0x1a) = 1;
      break;
    case 0xb:
      *(undefined *)(iVar5 + 0x1a) = 0;
      break;
    case 0xc:
      *(float *)(iVar5 + 4) = FLOAT_803e4830;
      break;
    case 0xd:
      *(float *)(iVar5 + 4) = FLOAT_803e4840;
      break;
    case 0xe:
      *(float *)(iVar5 + 4) = FLOAT_803e4844;
      break;
    case 0xf:
      *(float *)(iVar5 + 4) = FLOAT_803e4848;
      break;
    case 0x10:
      *(float *)(iVar5 + 8) = FLOAT_803e4830;
      break;
    case 0x11:
      *(float *)(iVar5 + 8) = FLOAT_803e4840;
      break;
    case 0x12:
      *(float *)(iVar5 + 8) = FLOAT_803e4844;
      break;
    case 0x13:
      *(float *)(iVar5 + 8) = FLOAT_803e4848;
      break;
    case 0x14:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4830;
      break;
    case 0x15:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4840;
      break;
    case 0x16:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4844;
      break;
    case 0x17:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4848;
      break;
    case 0x18:
      iVar3 = *(int *)(iVar5 + 0x10);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xbfff;
      }
      break;
    case 0x19:
      iVar3 = *(int *)(iVar5 + 0x10);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
      }
    }
    iVar7 = iVar7 + 1;
  } while( true );
}

