// Function: FUN_802aff58
// Entry: 802aff58
// Size: 788 bytes

void FUN_802aff58(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  bool bVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  
  iVar3 = FUN_802aa36c(param_9,param_10,0x2d);
  if (iVar3 == 0) {
    FUN_800201ac(0x965,1);
    FUN_800201ac(0x986,1);
  }
  else {
    FUN_800201ac(0x965,0);
    FUN_800201ac(0x986,0);
  }
  iVar3 = FUN_802aa36c(param_9,param_10,0x5ce);
  if (iVar3 == 0) {
    FUN_800201ac(0x961,1);
  }
  else {
    FUN_800201ac(0x961,0);
  }
  if (((*(int *)(param_10 + 0x2d0) == 0) &&
      (9 < *(short *)(*(int *)(*(int *)(param_9 + 0xb8) + 0x35c) + 4))) &&
     ((*(byte *)(*(int *)(param_9 + 0xb8) + 0x3f3) >> 3 & 1) == 0)) {
    if ((*(short *)(param_10 + 0x274) == 1) || (*(short *)(param_10 + 0x274) == 2)) {
      bVar1 = true;
    }
    else {
      bVar1 = false;
    }
  }
  else {
    bVar1 = false;
  }
  if (bVar1) {
    FUN_800201ac(0x969,0);
  }
  else {
    FUN_800201ac(0x969,1);
  }
  iVar3 = FUN_802aa05c(param_9,param_10);
  if (iVar3 == 0) {
    FUN_800201ac(0x960,1);
  }
  else {
    FUN_800201ac(0x960,0);
  }
  iVar3 = FUN_802a9f30(param_9,param_10);
  if (iVar3 == 0) {
    FUN_800201ac(0x964,1);
  }
  else {
    FUN_800201ac(0x964,0);
  }
  iVar3 = FUN_802aa16c(param_9,param_10);
  if (iVar3 == 0) {
    FUN_800201ac(0x96b,1);
  }
  else {
    FUN_800201ac(0x96b,0);
  }
  sVar2 = *(short *)(param_10 + 0x80a);
  if (sVar2 == 0x40) {
    uVar4 = FUN_80014e9c(0);
    if ((((uVar4 & 0x200) != 0) && ((*(byte *)(param_10 + 0x3f3) >> 3 & 1) != 0)) &&
       (*(char *)(param_10 + 0x8c8) != 'D')) {
      FUN_802965f0();
      *(undefined2 *)(param_10 + 0x80a) = 0xffff;
      *(undefined2 *)(param_10 + 0x80c) = 0xffff;
      FUN_80014b68(0,0x200);
    }
    *(float *)(param_10 + 0x854) = *(float *)(param_10 + 0x854) - FLOAT_803dc074;
    if (*(float *)(param_10 + 0x854) <= FLOAT_803e8b3c) {
      iVar3 = *(int *)(*(int *)(param_9 + 0xb8) + 0x35c);
      sVar2 = *(short *)(iVar3 + 4);
      if (sVar2 < 0) {
        sVar2 = 0;
      }
      else if (*(short *)(iVar3 + 6) < sVar2) {
        sVar2 = *(short *)(iVar3 + 6);
      }
      *(short *)(iVar3 + 4) = sVar2;
      *(float *)(param_10 + 0x854) = FLOAT_803e8b74;
    }
  }
  else if ((((0x3f < sVar2) && (sVar2 == 0x5ce)) && (DAT_803df0ac != '\0')) &&
          (iVar3 = FUN_80080490(), iVar3 != 0)) {
    *(undefined2 *)(param_10 + 0x80a) = 0xffff;
    DAT_803df0ac = '\0';
    iVar3 = 0;
    piVar5 = &DAT_80333b34;
    uVar6 = extraout_f1;
    do {
      if (*piVar5 != 0) {
        uVar6 = FUN_8002cc9c(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar5);
        *piVar5 = 0;
      }
      piVar5 = piVar5 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 7);
    if (DAT_803df0d4 != (undefined *)0x0) {
      FUN_80013e4c(DAT_803df0d4);
      DAT_803df0d4 = (undefined *)0x0;
    }
  }
  return;
}

