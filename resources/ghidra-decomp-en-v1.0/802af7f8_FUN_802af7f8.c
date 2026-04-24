// Function: FUN_802af7f8
// Entry: 802af7f8
// Size: 788 bytes

void FUN_802af7f8(int param_1,int param_2)

{
  bool bVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  
  iVar3 = FUN_802a9c0c(param_1,param_2,0x2d);
  if (iVar3 == 0) {
    FUN_800200e8(0x965,1);
    FUN_800200e8(0x986,1);
  }
  else {
    FUN_800200e8(0x965,0);
    FUN_800200e8(0x986,0);
  }
  iVar3 = FUN_802a9c0c(param_1,param_2,0x5ce);
  if (iVar3 == 0) {
    FUN_800200e8(0x961,1);
  }
  else {
    FUN_800200e8(0x961,0);
  }
  if (((*(int *)(param_2 + 0x2d0) == 0) &&
      (9 < *(short *)(*(int *)(*(int *)(param_1 + 0xb8) + 0x35c) + 4))) &&
     ((*(byte *)(*(int *)(param_1 + 0xb8) + 0x3f3) >> 3 & 1) == 0)) {
    if ((*(short *)(param_2 + 0x274) == 1) || (*(short *)(param_2 + 0x274) == 2)) {
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
    FUN_800200e8(0x969,0);
  }
  else {
    FUN_800200e8(0x969,1);
  }
  iVar3 = FUN_802a98fc(param_1,param_2);
  if (iVar3 == 0) {
    FUN_800200e8(0x960,1);
  }
  else {
    FUN_800200e8(0x960,0);
  }
  iVar3 = FUN_802a97d0(param_1,param_2);
  if (iVar3 == 0) {
    FUN_800200e8(0x964,1);
  }
  else {
    FUN_800200e8(0x964,0);
  }
  iVar3 = FUN_802a9a0c(param_1,param_2);
  if (iVar3 == 0) {
    FUN_800200e8(0x96b,1);
  }
  else {
    FUN_800200e8(0x96b,0);
  }
  sVar2 = *(short *)(param_2 + 0x80a);
  if (sVar2 == 0x40) {
    uVar4 = FUN_80014e70(0);
    if ((((uVar4 & 0x200) != 0) && ((*(byte *)(param_2 + 0x3f3) >> 3 & 1) != 0)) &&
       (*(char *)(param_2 + 0x8c8) != 'D')) {
      FUN_80295e90(param_1,0);
      *(undefined2 *)(param_2 + 0x80a) = 0xffff;
      *(undefined2 *)(param_2 + 0x80c) = 0xffff;
      FUN_80014b3c(0,0x200);
    }
    *(float *)(param_2 + 0x854) = *(float *)(param_2 + 0x854) - FLOAT_803db414;
    if (*(float *)(param_2 + 0x854) <= FLOAT_803e7ea4) {
      iVar3 = *(int *)(*(int *)(param_1 + 0xb8) + 0x35c);
      sVar2 = *(short *)(iVar3 + 4);
      if (sVar2 < 0) {
        sVar2 = 0;
      }
      else if (*(short *)(iVar3 + 6) < sVar2) {
        sVar2 = *(short *)(iVar3 + 6);
      }
      *(short *)(iVar3 + 4) = sVar2;
      *(float *)(param_2 + 0x854) = FLOAT_803e7edc;
    }
  }
  else if ((((0x3f < sVar2) && (sVar2 == 0x5ce)) && (DAT_803de42c != '\0')) &&
          (iVar3 = FUN_80080204(), iVar3 != 0)) {
    *(undefined2 *)(param_2 + 0x80a) = 0xffff;
    DAT_803de42c = '\0';
    iVar3 = 0;
    piVar5 = &DAT_80332ed4;
    do {
      if (*piVar5 != 0) {
        FUN_8002cbc4();
        *piVar5 = 0;
      }
      piVar5 = piVar5 + 1;
      iVar3 = iVar3 + 1;
    } while (iVar3 < 7);
    if (DAT_803de454 != 0) {
      FUN_80013e2c();
      DAT_803de454 = 0;
    }
  }
  return;
}

