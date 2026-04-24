// Function: FUN_80124d80
// Entry: 80124d80
// Size: 1220 bytes

void FUN_80124d80(void)

{
  short sVar2;
  short sVar3;
  int iVar1;
  short sVar4;
  int iVar5;
  double local_10;
  
  sVar2 = DAT_803dd79a * (ushort)DAT_803db410 * 1000;
  iVar5 = (int)sVar2;
  if (iVar5 != 0) {
    sVar3 = DAT_803dd79c - DAT_803dd79e;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    if (iVar5 < 0) {
      iVar5 = -iVar5;
    }
    iVar1 = (int)sVar3;
    if (iVar1 < 0) {
      iVar1 = -iVar1;
    }
    if (iVar5 < iVar1) {
      DAT_803dd79c = DAT_803dd79c + sVar2;
    }
    else {
      DAT_803dd79c = DAT_803dd79e;
      DAT_803dd79a = 0;
    }
    sVar2 = DAT_803dd79c;
    sVar3 = DAT_803dd79c - DAT_803dd79e;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    iVar5 = (int)sVar3;
    if (iVar5 < 0) {
      iVar5 = -iVar5;
    }
    if (iVar5 < 0x2aab) {
      DAT_803dd8b6 = DAT_803dd8b7;
    }
    *DAT_803a93ec = DAT_803dd79c;
    *DAT_803a93e0 = sVar2;
    *DAT_803a93f0 = sVar2 + 0x5555;
    *DAT_803a93e4 = sVar2 + 0x5555;
    *DAT_803a93f4 = sVar2 + -0x5556;
    *DAT_803a93e8 = sVar2 + -0x5556;
  }
  sVar2 = DAT_803dd79c;
  *DAT_803a93ec = DAT_803dd79c;
  *DAT_803a93e0 = sVar2;
  *DAT_803a93f0 = sVar2 + 0x5555;
  *DAT_803a93e4 = sVar2 + 0x5555;
  *DAT_803a93f4 = sVar2 + -0x5556;
  *DAT_803a93e8 = sVar2 + -0x5556;
  sVar2 = DAT_803dd79c;
  if (0x8000 < DAT_803dd79c) {
    sVar2 = DAT_803dd79c + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  sVar3 = DAT_803dd79c + -0x5555;
  if (0x8000 < sVar3) {
    sVar3 = DAT_803dd79c + -0x5554;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  sVar4 = DAT_803dd79c + 0x5556;
  if (0x8000 < sVar4) {
    sVar4 = DAT_803dd79c + 0x5557;
  }
  if (sVar4 < -0x8000) {
    sVar4 = sVar4 + -1;
  }
  iVar5 = (int)sVar3;
  if (iVar5 < 0) {
    iVar5 = -iVar5;
  }
  iVar1 = (int)sVar2;
  if (iVar1 < 0) {
    iVar1 = -iVar1;
  }
  if (iVar1 < iVar5) {
    sVar3 = sVar2;
    if (sVar2 < 0) {
      sVar3 = -sVar2;
    }
  }
  else if (sVar3 < 0) {
    sVar3 = -sVar3;
  }
  iVar5 = (int)sVar4;
  if (iVar5 < 0) {
    iVar5 = -iVar5;
  }
  if ((iVar5 <= sVar3) && (sVar3 = sVar4, sVar4 < 0)) {
    sVar3 = -sVar4;
  }
  local_10 = (double)CONCAT44(0x43300000,(int)sVar3 ^ 0x80000000);
  sVar2 = (short)(int)-(DOUBLE_803e2030 * (local_10 - DOUBLE_803e1e78) - DOUBLE_803e2028);
  if (sVar2 < 1) {
    sVar2 = 0;
  }
  DAT_803dd8d4 = (char)sVar2;
  return;
}

