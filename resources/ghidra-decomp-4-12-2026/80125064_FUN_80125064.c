// Function: FUN_80125064
// Entry: 80125064
// Size: 1220 bytes

void FUN_80125064(void)

{
  short sVar2;
  short sVar3;
  int iVar1;
  short sVar4;
  int iVar5;
  undefined8 local_10;
  
  sVar2 = DAT_803de41a * (ushort)DAT_803dc070 * 1000;
  iVar5 = (int)sVar2;
  if (iVar5 != 0) {
    sVar3 = DAT_803de41c - DAT_803de41e;
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
      DAT_803de41c = DAT_803de41c + sVar2;
    }
    else {
      DAT_803de41c = DAT_803de41e;
      DAT_803de41a = 0;
    }
    sVar2 = DAT_803de41c;
    sVar3 = DAT_803de41c - DAT_803de41e;
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
      DAT_803de536 = DAT_803de537;
    }
    *DAT_803aa04c = DAT_803de41c;
    *DAT_803aa040 = sVar2;
    *DAT_803aa050 = sVar2 + 0x5555;
    *DAT_803aa044 = sVar2 + 0x5555;
    *DAT_803aa054 = sVar2 + -0x5556;
    *DAT_803aa048 = sVar2 + -0x5556;
  }
  sVar2 = DAT_803de41c;
  *DAT_803aa04c = DAT_803de41c;
  *DAT_803aa040 = sVar2;
  *DAT_803aa050 = sVar2 + 0x5555;
  *DAT_803aa044 = sVar2 + 0x5555;
  *DAT_803aa054 = sVar2 + -0x5556;
  *DAT_803aa048 = sVar2 + -0x5556;
  sVar2 = DAT_803de41c;
  if (0x8000 < DAT_803de41c) {
    sVar2 = DAT_803de41c + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  sVar3 = DAT_803de41c + -0x5555;
  if (0x8000 < sVar3) {
    sVar3 = DAT_803de41c + -0x5554;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  sVar4 = DAT_803de41c + 0x5556;
  if (0x8000 < sVar4) {
    sVar4 = DAT_803de41c + 0x5557;
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
  sVar2 = (short)(int)-(DOUBLE_803e2cb0 * (local_10 - DOUBLE_803e2af8) - DOUBLE_803e2ca8);
  if (sVar2 < 1) {
    sVar2 = 0;
  }
  DAT_803de554 = (char)sVar2;
  return;
}

