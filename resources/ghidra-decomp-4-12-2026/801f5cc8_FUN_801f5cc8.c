// Function: FUN_801f5cc8
// Entry: 801f5cc8
// Size: 1116 bytes

undefined4
FUN_801f5cc8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,undefined *param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            int param_15,undefined4 param_16)

{
  undefined4 uVar1;
  int iVar2;
  undefined *puVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  undefined auStack_28 [24];
  
  iVar4 = *(int *)(param_9 + 0xb8);
  puVar3 = param_11;
  if ((*(byte *)(iVar4 + 0x12) & 1) != 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x7d8,0,2,0xffffffff,0);
    puVar3 = auStack_28;
    param_12 = 2;
    param_13 = 0xffffffff;
    param_14 = 0;
    param_15 = *DAT_803dd708;
    param_1 = (**(code **)(param_15 + 8))(param_9,0x7d8);
  }
  param_11[0x56] = 0;
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
  *(undefined **)(param_11 + 0xe8) = &DAT_801f5cc4;
  iVar5 = 0;
  do {
    if ((int)(uint)(byte)param_11[0x8b] <= iVar5) {
      return 0;
    }
    switch(param_11[iVar5 + 0x81]) {
    case 1:
      puVar3 = (undefined *)0x1;
      FUN_80043604(0,0,1);
      break;
    case 2:
      iVar2 = *(int *)(*(int *)(param_9 + 0x4c) + 0x14);
      if (iVar2 == 0x49781) {
        FUN_80043070(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42);
        uVar1 = FUN_8004832c(0x42);
        FUN_80043658(uVar1,0);
        uVar1 = FUN_8004832c(0xb);
        FUN_80043658(uVar1,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0x42,3);
        puVar3 = (undefined *)*DAT_803dd72c;
        param_1 = (**(code **)(puVar3 + 0x44))(7,5);
      }
      else if (iVar2 < 0x49781) {
        if (iVar2 == 0x47295) {
          FUN_80043070(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42);
          uVar1 = FUN_8004832c(0x42);
          FUN_80043658(uVar1,0);
          uVar1 = FUN_8004832c(0xb);
          FUN_80043658(uVar1,1);
          (**(code **)(*DAT_803dd72c + 0x44))(0x42,3);
          puVar3 = (undefined *)*DAT_803dd72c;
          param_1 = (**(code **)(puVar3 + 0x44))(7,4);
        }
        else if ((iVar2 < 0x47295) && (iVar2 == 0x2183)) {
          uVar1 = FUN_8004832c(0x41);
          FUN_80043658(uVar1,0);
          uVar1 = FUN_8004832c(0xb);
          FUN_80043658(uVar1,1);
          param_1 = (**(code **)(*DAT_803dd72c + 0x78))(1);
        }
      }
      else if (iVar2 == 0x4a1c0) {
        FUN_80043070(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42);
        uVar1 = FUN_8004832c(0x42);
        FUN_80043658(uVar1,0);
        uVar1 = FUN_8004832c(0xb);
        FUN_80043658(uVar1,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0x42,3);
        puVar3 = (undefined *)*DAT_803dd72c;
        param_1 = (**(code **)(puVar3 + 0x44))(7,7);
      }
      break;
    case 3:
      iVar2 = *(int *)(*(int *)(param_9 + 0x4c) + 0x14);
      if (iVar2 == 0x49781) {
        param_1 = FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7e,
                               '\0',puVar3,param_12,param_13,param_14,param_15,param_16);
      }
      else if (iVar2 < 0x49781) {
        if (iVar2 == 0x47295) {
          param_1 = FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 0x7e,'\0',puVar3,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else if (iVar2 == 0x4a1c0) {
        param_1 = FUN_80055464(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7e,
                               '\0',puVar3,param_12,param_13,param_14,param_15,param_16);
      }
      break;
    case 4:
      iVar2 = *(int *)(*(int *)(param_9 + 0x4c) + 0x14);
      if (iVar2 == 0x4a1c0) {
LAB_801f5e8c:
        *(undefined *)(iVar4 + 0x14) = 1;
      }
      else if (iVar2 < 0x4a1c0) {
        if ((iVar2 == 0x49781) || ((iVar2 < 0x49781 && (iVar2 == 0x47295)))) goto LAB_801f5e8c;
      }
      else if ((iVar2 == 0x4a5e6) || ((iVar2 < 0x4a5e6 && (iVar2 == 0x4a250)))) goto LAB_801f5e8c;
      break;
    case 5:
      *(byte *)(iVar4 + 0x12) = *(byte *)(iVar4 + 0x12) | 1;
      break;
    case 6:
      *(byte *)(iVar4 + 0x12) = *(byte *)(iVar4 + 0x12) & 0xfe;
      break;
    case 7:
      FUN_80088f20(7,'\0');
      uVar6 = FUN_8005d06c(1);
      uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x84,0,param_13,param_14,param_15,param_16);
      uVar6 = FUN_80008cbc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x8a,0,param_13,param_14,param_15,param_16);
      uVar6 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x217,0
                           ,param_13,param_14,param_15,param_16);
      puVar3 = (undefined *)0x216;
      param_12 = 0;
      param_1 = FUN_80008b74(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x216
                             ,0,param_13,param_14,param_15,param_16);
      break;
    case 8:
      param_1 = FUN_80055228(1);
      break;
    case 9:
      param_1 = FUN_80055228(0);
    }
    iVar5 = iVar5 + 1;
  } while( true );
}

