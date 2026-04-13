// Function: FUN_8023a02c
// Entry: 8023a02c
// Size: 996 bytes

undefined4
FUN_8023a02c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  short *psVar1;
  undefined4 uVar2;
  int iVar3;
  int *piVar4;
  undefined8 uVar5;
  
  piVar4 = *(int **)(param_9 + 0xb8);
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)(param_11 + iVar3 + 0x81)) {
    case 1:
      FUN_8008999c(7,1,0);
      param_13 = 0;
      param_14 = 0;
      FUN_8008986c(7,0x96,200,0xf0,0,0);
      param_2 = (double)FLOAT_803e80fc;
      param_3 = (double)FLOAT_803e8100;
      uVar5 = FUN_80089734((double)FLOAT_803e80f8,param_2,param_3,7);
      param_12 = 0;
      param_1 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             param_9,0x21f,0,param_13,param_14,param_15,param_16);
      break;
    case 2:
      FUN_8008999c(7,1,0);
      param_13 = 0;
      param_14 = 0;
      FUN_8008986c(7,(byte)(int)FLOAT_803e8108,(byte)(int)FLOAT_803e810c,(byte)(int)FLOAT_803e8110,0
                   ,0);
      param_3 = (double)FLOAT_803e80fc;
      param_2 = (double)FLOAT_803e8114;
      uVar5 = FUN_80089734(param_3,param_2,param_3,7);
      param_12 = 0;
      param_1 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             param_9,0x21d,0,param_13,param_14,param_15,param_16);
      break;
    case 3:
      param_1 = FUN_80239f50(param_9);
      if (*piVar4 != 0) {
        param_1 = FUN_802341d0(*piVar4,'\x01');
      }
      break;
    case 4:
      param_1 = FUN_80239f50(param_9);
      if (*piVar4 != 0) {
        param_1 = FUN_802341d0(*piVar4,'\0');
      }
      break;
    case 5:
      FUN_8008999c(7,1,0);
      param_13 = 0;
      param_14 = 0;
      FUN_8008986c(7,0x96,200,0xf0,0,0);
      param_2 = (double)FLOAT_803e8114;
      param_3 = (double)FLOAT_803e80fc;
      uVar5 = FUN_80089734((double)FLOAT_803e8118,param_2,param_3,7);
      param_12 = 0;
      param_1 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             param_9,0x21e,0,param_13,param_14,param_15,param_16);
      break;
    case 6:
      FUN_80043070(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
      break;
    case 7:
      FUN_80043604(0,0,1);
      FUN_80043604(0,1,1);
      FUN_8004832c(0xb);
      param_1 = FUN_80043938(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      break;
    case 8:
      piVar4[3] = (int)FLOAT_803e8104;
      break;
    case 9:
      uVar2 = 1;
      FUN_80043604(0,0,1);
      uVar5 = FUN_80014974(4);
      FUN_80055464(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x12,'\0',uVar2,
                   param_12,param_13,param_14,param_15,param_16);
      param_1 = FUN_80134f4c();
      break;
    case 10:
      FUN_8008999c(7,1,0);
      param_13 = 0;
      param_14 = 0;
      FUN_8008986c(7,0x96,200,0xf0,0,0);
      param_2 = (double)FLOAT_803e8114;
      param_3 = (double)FLOAT_803e80fc;
      uVar5 = FUN_80089734((double)FLOAT_803e811c,param_2,param_3,7);
      param_12 = 0;
      param_1 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             param_9,0x21f,0,param_13,param_14,param_15,param_16);
      break;
    case 0xb:
      FUN_8008999c(7,1,0);
      param_13 = 0;
      param_14 = 0;
      FUN_8008986c(7,(byte)(int)FLOAT_803e8108,(byte)(int)FLOAT_803e810c,(byte)(int)FLOAT_803e8110,0
                   ,0);
      param_2 = (double)FLOAT_803e8114;
      param_3 = (double)FLOAT_803e80fc;
      uVar5 = FUN_80089734((double)FLOAT_803e811c,param_2,param_3,7);
      param_12 = 0;
      param_1 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             param_9,0x21d,0,param_13,param_14,param_15,param_16);
    }
  }
  if ((double)FLOAT_803e8120 < (double)(float)piVar4[3]) {
    FUN_800168a8((double)(float)piVar4[3],param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 0x476);
    piVar4[3] = (int)((float)piVar4[3] - FLOAT_803dc074);
    if ((float)piVar4[3] < FLOAT_803e8120) {
      piVar4[3] = (int)FLOAT_803e8120;
    }
  }
  psVar1 = (short *)piVar4[1];
  if (psVar1 != (short *)0x0) {
    *psVar1 = *psVar1 + (short)(int)(FLOAT_803e8124 * FLOAT_803dc074);
  }
  psVar1 = (short *)piVar4[2];
  if (psVar1 != (short *)0x0) {
    *psVar1 = *psVar1 - (short)(int)(FLOAT_803e8124 * FLOAT_803dc074);
  }
  return 0;
}

