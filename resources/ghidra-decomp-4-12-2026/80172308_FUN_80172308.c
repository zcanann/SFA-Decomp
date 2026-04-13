// Function: FUN_80172308
// Entry: 80172308
// Size: 744 bytes

void FUN_80172308(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  short sVar1;
  char cVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  iVar5 = *(int *)(param_9 + 0x4c);
  iVar4 = *(int *)(*(int *)(param_9 + 0x50) + 0x18);
  FUN_8002bac4();
  FUN_8002ba84();
  FUN_8002bac4();
  FUN_8002ba84();
  uVar7 = FUN_80035ff8(param_9);
  if ((*(ushort *)(param_9 + 6) & 0x2000) != 0) {
    *(float *)(iVar6 + 8) = FLOAT_803e40e8;
    if (*(int *)(param_9 + 100) != 0) {
      *(undefined4 *)(*(int *)(param_9 + 100) + 0x30) = 0x1000;
    }
  }
  if ((int)*(short *)(iVar6 + 0x10) != 0xffffffff) {
    FUN_800201ac((int)*(short *)(iVar6 + 0x10),1);
    uVar7 = FUN_800e83ec(param_9);
  }
  uVar3 = (uint)*(short *)(iVar5 + 0x1e);
  if (uVar3 != 0xffffffff) {
    uVar7 = FUN_800201ac(uVar3,1);
  }
  uVar3 = (uint)*(short *)(iVar5 + 0x2c);
  if (0 < (int)uVar3) {
    FUN_80020000(uVar3);
  }
  sVar1 = *(short *)(iVar4 + 2);
  if (sVar1 == 4) {
    sVar1 = *(short *)(param_9 + 0x46);
    if (sVar1 == 0x3cd) {
      iVar4 = FUN_8002bac4();
      FUN_8029725c(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,2);
      uVar3 = FUN_8002bac4();
      FUN_8000bb38(uVar3,0x49);
      FUN_80099c40((double)FLOAT_803e40ec,param_9,1,0x28);
    }
    else if ((sVar1 < 0x3cd) && (sVar1 == 0xb)) {
      uVar3 = FUN_8002bac4();
      uVar7 = FUN_8000bb38(uVar3,0x49);
      iVar4 = FUN_8002bac4();
      FUN_8029725c(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,4);
      FUN_80099c40((double)FLOAT_803e40ec,param_9,3,0x28);
    }
    else {
      uVar3 = FUN_8002bac4();
      FUN_8000bb38(uVar3,0x58);
      FUN_80099c40((double)FLOAT_803e40ec,param_9,0xff,0x28);
    }
  }
  else if ((sVar1 < 4) && (sVar1 == 1)) {
    sVar1 = *(short *)(param_9 + 0x46);
    if (sVar1 == 0x319) {
      FUN_8000bb38(param_9,0x16a);
      FUN_800201ac(0x3e9,1);
      *(undefined2 *)(iVar6 + 0x3c) = 0x4b0;
      FUN_80099c40((double)FLOAT_803e40ec,param_9,0xff,0x28);
    }
    else {
      if (sVar1 < 0x319) {
        if (sVar1 == 0x5a) {
          FUN_8000bb38(param_9,0x49);
          FUN_80099c40((double)FLOAT_803e40ec,param_9,2,0x28);
          goto LAB_801725bc;
        }
        if ((sVar1 < 0x5a) && (sVar1 == 0x22)) {
          FUN_8000bb38(param_9,0x49);
          FUN_80099c40((double)FLOAT_803e40ec,param_9,0xff,0x28);
          goto LAB_801725bc;
        }
      }
      else if (sVar1 == 0x6a6) {
        uVar3 = FUN_80020078(0x86a);
        cVar2 = (char)uVar3;
        if (cVar2 < '\a') {
          cVar2 = cVar2 + '\x01';
        }
        FUN_800201ac(0x86a,(int)cVar2);
        FUN_80099c40((double)FLOAT_803e40ec,param_9,6,0x28);
        FUN_8000bb38(param_9,0x49);
        goto LAB_801725bc;
      }
      FUN_8000bb38(param_9,0x58);
      FUN_80099c40((double)FLOAT_803e40ec,param_9,0xff,0x28);
    }
  }
  else {
    FUN_8000bb38(param_9,0x58);
    FUN_80099c40((double)FLOAT_803e40ec,param_9,0xff,0x28);
  }
LAB_801725bc:
  *(undefined4 *)(param_9 + 8) = *(undefined4 *)(*(int *)(param_9 + 0x50) + 4);
  *(undefined4 *)(param_9 + 0xf4) = 1;
  return;
}

