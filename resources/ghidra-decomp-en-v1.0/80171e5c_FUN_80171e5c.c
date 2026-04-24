// Function: FUN_80171e5c
// Entry: 80171e5c
// Size: 744 bytes

void FUN_80171e5c(int param_1)

{
  short sVar1;
  int iVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  iVar5 = *(int *)(*(int *)(param_1 + 0x50) + 0x18);
  FUN_8002b9ec();
  FUN_8002b9ac();
  FUN_8002b9ec();
  FUN_8002b9ac();
  FUN_80035f00(param_1);
  if ((*(ushort *)(param_1 + 6) & 0x2000) != 0) {
    *(float *)(iVar7 + 8) = FLOAT_803e3450;
    if (*(int *)(param_1 + 100) != 0) {
      *(undefined4 *)(*(int *)(param_1 + 100) + 0x30) = 0x1000;
    }
  }
  if (*(short *)(iVar7 + 0x10) != -1) {
    FUN_800200e8((int)*(short *)(iVar7 + 0x10),1);
    FUN_800e8168(param_1);
  }
  iVar2 = (int)*(short *)(iVar6 + 0x1e);
  if (iVar2 != -1) {
    FUN_800200e8(iVar2,1);
  }
  if (0 < *(short *)(iVar6 + 0x2c)) {
    FUN_8001ff3c();
  }
  sVar1 = *(short *)(iVar5 + 2);
  if (sVar1 == 4) {
    sVar1 = *(short *)(param_1 + 0x46);
    if (sVar1 == 0x3cd) {
      uVar3 = FUN_8002b9ec();
      FUN_80296afc(uVar3,2);
      uVar3 = FUN_8002b9ec();
      FUN_8000bb18(uVar3,0x49);
      FUN_800999b4((double)FLOAT_803e3454,param_1,1,0x28);
    }
    else if ((sVar1 < 0x3cd) && (sVar1 == 0xb)) {
      uVar3 = FUN_8002b9ec();
      FUN_8000bb18(uVar3,0x49);
      uVar3 = FUN_8002b9ec();
      FUN_80296afc(uVar3,4);
      FUN_800999b4((double)FLOAT_803e3454,param_1,3,0x28);
    }
    else {
      uVar3 = FUN_8002b9ec();
      FUN_8000bb18(uVar3,0x58);
      FUN_800999b4((double)FLOAT_803e3454,param_1,0xff,0x28);
    }
  }
  else if ((sVar1 < 4) && (sVar1 == 1)) {
    sVar1 = *(short *)(param_1 + 0x46);
    if (sVar1 == 0x319) {
      FUN_8000bb18(param_1,0x16a);
      FUN_800200e8(0x3e9,1);
      *(undefined2 *)(iVar7 + 0x3c) = 0x4b0;
      FUN_800999b4((double)FLOAT_803e3454,param_1,0xff,0x28);
    }
    else {
      if (sVar1 < 0x319) {
        if (sVar1 == 0x5a) {
          FUN_8000bb18(param_1,0x49);
          FUN_800999b4((double)FLOAT_803e3454,param_1,2,0x28);
          goto LAB_80172110;
        }
        if ((sVar1 < 0x5a) && (sVar1 == 0x22)) {
          FUN_8000bb18(param_1,0x49);
          FUN_800999b4((double)FLOAT_803e3454,param_1,0xff,0x28);
          goto LAB_80172110;
        }
      }
      else if (sVar1 == 0x6a6) {
        cVar4 = FUN_8001ffb4(0x86a);
        if (cVar4 < '\a') {
          cVar4 = cVar4 + '\x01';
        }
        FUN_800200e8(0x86a,(int)cVar4);
        FUN_800999b4((double)FLOAT_803e3454,param_1,6,0x28);
        FUN_8000bb18(param_1,0x49);
        goto LAB_80172110;
      }
      FUN_8000bb18(param_1,0x58);
      FUN_800999b4((double)FLOAT_803e3454,param_1,0xff,0x28);
    }
  }
  else {
    FUN_8000bb18(param_1,0x58);
    FUN_800999b4((double)FLOAT_803e3454,param_1,0xff,0x28);
  }
LAB_80172110:
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(param_1 + 0x50) + 4);
  *(undefined4 *)(param_1 + 0xf4) = 1;
  return;
}

