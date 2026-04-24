// Function: FUN_801d4d8c
// Entry: 801d4d8c
// Size: 1280 bytes

void FUN_801d4d8c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar4;
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar5;
  
  pbVar5 = *(byte **)(param_9 + 0x5c);
  pbVar5[2] = pbVar5[2] & 0xdf;
  bVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_9 + 0x56));
  if ((pbVar5[2] & 1) == 0) {
    if (bVar4 == 2) {
      uVar3 = FUN_80020078(0xc2);
      if (uVar3 == 6) {
        (**(code **)(*DAT_803dd6d4 + 0x54))(param_9,0x18f6);
        (**(code **)(*DAT_803dd6d4 + 0x48))(6,param_9,1);
        *pbVar5 = 3;
      }
      else {
        uVar3 = FUN_80020078(0xbf);
        if (uVar3 != 0) {
          *pbVar5 = 1;
        }
        pbVar5[2] = pbVar5[2] | 0xc;
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dcc34;
      }
    }
    else if (bVar4 < 2) {
      if (bVar4 != 0) {
        uVar1 = FUN_80036f50(0xf,param_9,(float *)0x0);
        (**(code **)(*DAT_803dd6d4 + 0x54))(uVar1,0x1324);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar1,0x10);
        pbVar5[2] = pbVar5[2] | 0xc;
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dcc30;
      }
    }
    else if (bVar4 == 8) {
      uVar1 = FUN_80036f50(0xf,param_9,(float *)0x0);
      (**(code **)(*DAT_803dd6d4 + 0x54))(uVar1,0x6a4);
      (**(code **)(*DAT_803dd6d4 + 0x48))(7,uVar1,8);
      *pbVar5 = 4;
      *(undefined **)(pbVar5 + 0x38) = &DAT_803dcc50;
    }
    else if (bVar4 < 8) {
      (**(code **)(*DAT_803dd6d4 + 0x54))(param_9,0x18f6);
      (**(code **)(*DAT_803dd6d4 + 0x48))(6,param_9,1);
      *pbVar5 = 3;
    }
    pbVar5[2] = pbVar5[2] | 1;
  }
  else {
    switch(bVar4) {
    case 2:
      FUN_801d4a94(param_9,pbVar5);
      break;
    case 3:
    case 4:
      uVar3 = FUN_80020078(0x193);
      if (uVar3 == 0) {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dcc3c;
      }
      else {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dcc54;
      }
      iVar2 = FUN_8002bac4();
      pbVar5[8] = 1;
      *(undefined4 *)(pbVar5 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(pbVar5 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(pbVar5 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_8003b5f8(param_9,(char *)(pbVar5 + 8));
      break;
    case 5:
      FUN_801d4954(param_9,(int)pbVar5);
      break;
    case 6:
      uVar3 = FUN_80020078(0x13f);
      if (uVar3 == 0) {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dcc48;
      }
      else {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dcc54;
      }
      iVar2 = FUN_8002bac4();
      pbVar5[8] = 1;
      *(undefined4 *)(pbVar5 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(pbVar5 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(pbVar5 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_8003b5f8(param_9,(char *)(pbVar5 + 8));
      break;
    case 7:
      uVar3 = FUN_80020078(0x199);
      if (uVar3 == 0) {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dcc4c;
      }
      else {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dcc54;
      }
      iVar2 = FUN_8002bac4();
      pbVar5[8] = 1;
      *(undefined4 *)(pbVar5 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(pbVar5 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(pbVar5 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_8003b5f8(param_9,(char *)(pbVar5 + 8));
      break;
    case 8:
      iVar2 = FUN_8002bac4();
      pbVar5[8] = 1;
      *(undefined4 *)(pbVar5 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(pbVar5 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(pbVar5 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_8003b5f8(param_9,(char *)(pbVar5 + 8));
    }
    if ((pbVar5[2] & 8) == 0) {
      FUN_8003b408((int)param_9,(int)(pbVar5 + 8));
    }
    else {
      FUN_8003b320((int)param_9,(int)(pbVar5 + 8));
    }
    if ((int)param_9[0x50] != (int)*(short *)(&DAT_80327a58 + (uint)*pbVar5 * 2)) {
      FUN_8003042c((double)FLOAT_803e6090,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(int)*(short *)(&DAT_80327a58 + (uint)*pbVar5 * 2),0,param_12,param_13,
                   param_14,param_15,param_16);
    }
    FUN_8002fb40((double)*(float *)(&DAT_80327a64 + (uint)*pbVar5 * 4),(double)FLOAT_803dc074);
    if ((pbVar5[2] & 0x10) == 0) {
      pbVar5[2] = pbVar5[2] & 0xfd;
      iVar2 = FUN_8003811c((int)param_9);
      if ((iVar2 != 0) && (*(char *)(*(int *)(param_9 + 0x3c) + 4) != '\x04')) {
        uVar3 = FUN_80022264(1,(uint)**(byte **)(pbVar5 + 0x38));
        pbVar5[2] = pbVar5[2] | 2;
        (**(code **)(*DAT_803dd6d4 + 0x48))
                  (*(undefined *)(*(int *)(pbVar5 + 0x38) + (uVar3 & 0xff)),param_9,0xffffffff);
      }
    }
    uVar3 = FUN_80022150((double)FLOAT_803e609c,(double)FLOAT_803e60a0,(float *)(pbVar5 + 0x3c));
    if (uVar3 != 0) {
      FUN_8000bb38((uint)param_9,0x410);
    }
  }
  return;
}

