// Function: FUN_801d5ed4
// Entry: 801d5ed4
// Size: 644 bytes

void FUN_801d5ed4(uint param_1,int param_2,int param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  double dVar5;
  
  *(undefined **)(param_2 + 0x62c) = &DAT_803dcc64;
  iVar2 = FUN_8002bac4();
  dVar5 = FUN_80021730((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
  bVar4 = dVar5 < (double)FLOAT_803e60bc;
  if (*(char *)(param_3 + 0x1a) == '\0') {
    uVar3 = FUN_80020078(0x13e);
    if (uVar3 == 0) {
      iVar2 = FUN_8003811c(param_1);
      if (iVar2 != 0) {
        *(byte *)(param_2 + 0x625) = *(byte *)(param_2 + 0x625) | 4;
        FUN_800201ac(0xcd5,1);
      }
    }
    else {
      uVar3 = FUN_80020078(0x168);
      if (uVar3 == 0) {
        iVar2 = FUN_8003811c(param_1);
        if (iVar2 != 0) {
          *(byte *)(param_2 + 0x625) = *(byte *)(param_2 + 0x625) | 4;
          FUN_800201ac(0xcd6,1);
        }
      }
      else {
        *(byte *)(param_2 + 0x625) = *(byte *)(param_2 + 0x625) | 0x10;
        *(undefined *)(param_2 + 0x63f) = 0;
        bVar4 = false;
      }
    }
  }
  else {
    uVar3 = FUN_80020078(0x1ab);
    if (uVar3 != 0) {
      bVar4 = false;
    }
  }
  cVar1 = *(char *)(param_2 + 0x624);
  if (cVar1 == '\v') {
    if ((*(byte *)(param_2 + 0x625) & 1) != 0) {
      if (bVar4) {
        *(undefined *)(param_2 + 0x624) = 0xd;
      }
      else {
        *(undefined *)(param_2 + 0x627) = 2;
        *(undefined *)(param_2 + 0x624) = 0xc;
      }
    }
  }
  else if (cVar1 < '\v') {
    if (cVar1 == '\x01') {
      if (bVar4) {
        *(undefined *)(param_2 + 0x624) = 0;
      }
      else {
        *(float *)(param_2 + 0x630) = *(float *)(param_2 + 0x630) - FLOAT_803dc074;
        if (*(float *)(param_2 + 0x630) <= FLOAT_803e60b0) {
          *(undefined *)(param_2 + 0x624) = 0xb;
        }
      }
    }
    else if (((cVar1 < '\x01') && (-1 < cVar1)) && (!bVar4)) {
      *(float *)(param_2 + 0x630) = FLOAT_803e60d0;
      *(undefined *)(param_2 + 0x624) = 1;
    }
  }
  else if (cVar1 == '\r') {
    if ((*(byte *)(param_2 + 0x625) & 1) != 0) {
      *(undefined *)(param_2 + 0x624) = 0;
      uVar3 = FUN_80022264(1000,2000);
      *(float *)(param_2 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e60c0);
    }
  }
  else if (cVar1 < '\r') {
    if (bVar4) {
      *(undefined *)(param_2 + 0x624) = 0xd;
    }
    else {
      FUN_801d5470(param_1,param_2);
    }
  }
  return;
}

