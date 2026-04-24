// Function: FUN_801d479c
// Entry: 801d479c
// Size: 1280 bytes

void FUN_801d479c(int param_1)

{
  byte bVar4;
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar5;
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  pbVar5[2] = pbVar5[2] & 0xdf;
  bVar4 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  if ((pbVar5[2] & 1) == 0) {
    if (bVar4 == 2) {
      iVar2 = FUN_8001ffb4(0xc2);
      if (iVar2 == 6) {
        (**(code **)(*DAT_803dca54 + 0x54))(param_1,0x18f6);
        (**(code **)(*DAT_803dca54 + 0x48))(6,param_1,1);
        *pbVar5 = 3;
      }
      else {
        iVar2 = FUN_8001ffb4(0xbf);
        if (iVar2 != 0) {
          *pbVar5 = 1;
        }
        pbVar5[2] = pbVar5[2] | 0xc;
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dbfcc;
      }
    }
    else if (bVar4 < 2) {
      if (bVar4 != 0) {
        uVar1 = FUN_80036e58(0xf,param_1,0);
        (**(code **)(*DAT_803dca54 + 0x54))(uVar1,0x1324);
        (**(code **)(*DAT_803dca54 + 0x48))(1,uVar1,0x10);
        pbVar5[2] = pbVar5[2] | 0xc;
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dbfc8;
      }
    }
    else if (bVar4 == 8) {
      uVar1 = FUN_80036e58(0xf,param_1,0);
      (**(code **)(*DAT_803dca54 + 0x54))(uVar1,0x6a4);
      (**(code **)(*DAT_803dca54 + 0x48))(7,uVar1,8);
      *pbVar5 = 4;
      *(undefined **)(pbVar5 + 0x38) = &DAT_803dbfe8;
    }
    else if (bVar4 < 8) {
      (**(code **)(*DAT_803dca54 + 0x54))(param_1,0x18f6);
      (**(code **)(*DAT_803dca54 + 0x48))(6,param_1,1);
      *pbVar5 = 3;
    }
    pbVar5[2] = pbVar5[2] | 1;
  }
  else {
    switch(bVar4) {
    case 2:
      FUN_801d44a4(param_1,pbVar5);
      break;
    case 3:
    case 4:
      iVar2 = FUN_8001ffb4(0x193);
      if (iVar2 == 0) {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dbfd4;
      }
      else {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dbfec;
      }
      iVar2 = FUN_8002b9ec();
      pbVar5[8] = 1;
      *(undefined4 *)(pbVar5 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(pbVar5 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(pbVar5 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_8003b500((double)FLOAT_803e53f8,param_1,pbVar5 + 8);
      break;
    case 5:
      FUN_801d4364(param_1,pbVar5);
      break;
    case 6:
      iVar2 = FUN_8001ffb4(0x13f);
      if (iVar2 == 0) {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dbfe0;
      }
      else {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dbfec;
      }
      iVar2 = FUN_8002b9ec();
      pbVar5[8] = 1;
      *(undefined4 *)(pbVar5 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(pbVar5 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(pbVar5 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_8003b500((double)FLOAT_803e53f8,param_1,pbVar5 + 8);
      break;
    case 7:
      iVar2 = FUN_8001ffb4(0x199);
      if (iVar2 == 0) {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dbfe4;
      }
      else {
        *(undefined **)(pbVar5 + 0x38) = &DAT_803dbfec;
      }
      iVar2 = FUN_8002b9ec();
      pbVar5[8] = 1;
      *(undefined4 *)(pbVar5 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(pbVar5 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(pbVar5 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_8003b500((double)FLOAT_803e53f8,param_1,pbVar5 + 8);
      break;
    case 8:
      iVar2 = FUN_8002b9ec();
      pbVar5[8] = 1;
      *(undefined4 *)(pbVar5 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(pbVar5 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(pbVar5 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_8003b500((double)FLOAT_803e53f8,param_1,pbVar5 + 8);
    }
    if ((pbVar5[2] & 8) == 0) {
      FUN_8003b310(param_1,pbVar5 + 8);
    }
    else {
      FUN_8003b228(param_1,pbVar5 + 8);
    }
    if ((int)*(short *)(param_1 + 0xa0) != (int)*(short *)(&DAT_80326e18 + (uint)*pbVar5 * 2)) {
      FUN_80030334((double)FLOAT_803e53f8,param_1,(int)*(short *)(&DAT_80326e18 + (uint)*pbVar5 * 2)
                   ,0);
    }
    FUN_8002fa48((double)*(float *)(&DAT_80326e24 + (uint)*pbVar5 * 4),(double)FLOAT_803db414,
                 param_1,0);
    if ((pbVar5[2] & 0x10) == 0) {
      pbVar5[2] = pbVar5[2] & 0xfd;
      iVar2 = FUN_80038024(param_1);
      if ((iVar2 != 0) && (*(char *)(*(int *)(param_1 + 0x78) + 4) != '\x04')) {
        uVar3 = FUN_800221a0(1,**(undefined **)(pbVar5 + 0x38));
        pbVar5[2] = pbVar5[2] | 2;
        (**(code **)(*DAT_803dca54 + 0x48))
                  (*(undefined *)(*(int *)(pbVar5 + 0x38) + (uVar3 & 0xff)),param_1,0xffffffff);
      }
    }
    iVar2 = FUN_8002208c((double)FLOAT_803e5404,(double)FLOAT_803e5408,pbVar5 + 0x3c);
    if (iVar2 != 0) {
      FUN_8000bb18(param_1,0x410);
    }
  }
  return;
}

