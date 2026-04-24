// Function: FUN_801d58e4
// Entry: 801d58e4
// Size: 644 bytes

void FUN_801d58e4(int param_1,int param_2,int param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  double dVar5;
  
  *(undefined **)(param_2 + 0x62c) = &DAT_803dbffc;
  iVar2 = FUN_8002b9ec();
  dVar5 = (double)FUN_8002166c(param_1 + 0x18,iVar2 + 0x18);
  bVar4 = dVar5 < (double)FLOAT_803e5424;
  if (*(char *)(param_3 + 0x1a) == '\0') {
    iVar2 = FUN_8001ffb4(0x13e);
    if (iVar2 == 0) {
      iVar2 = FUN_80038024(param_1);
      if (iVar2 != 0) {
        *(byte *)(param_2 + 0x625) = *(byte *)(param_2 + 0x625) | 4;
        FUN_800200e8(0xcd5,1);
      }
    }
    else {
      iVar2 = FUN_8001ffb4(0x168);
      if (iVar2 == 0) {
        iVar2 = FUN_80038024(param_1);
        if (iVar2 != 0) {
          *(byte *)(param_2 + 0x625) = *(byte *)(param_2 + 0x625) | 4;
          FUN_800200e8(0xcd6,1);
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
    iVar2 = FUN_8001ffb4(0x1ab);
    if (iVar2 != 0) {
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
        *(float *)(param_2 + 0x630) = *(float *)(param_2 + 0x630) - FLOAT_803db414;
        if (*(float *)(param_2 + 0x630) <= FLOAT_803e5418) {
          *(undefined *)(param_2 + 0x624) = 0xb;
        }
      }
    }
    else if (((cVar1 < '\x01') && (-1 < cVar1)) && (!bVar4)) {
      *(float *)(param_2 + 0x630) = FLOAT_803e5438;
      *(undefined *)(param_2 + 0x624) = 1;
    }
  }
  else if (cVar1 == '\r') {
    if ((*(byte *)(param_2 + 0x625) & 1) != 0) {
      *(undefined *)(param_2 + 0x624) = 0;
      uVar3 = FUN_800221a0(1000,2000);
      *(float *)(param_2 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e5428);
    }
  }
  else if (cVar1 < '\r') {
    if (bVar4) {
      *(undefined *)(param_2 + 0x624) = 0xd;
    }
    else {
      FUN_801d4e80(param_1,param_2);
    }
  }
  return;
}

