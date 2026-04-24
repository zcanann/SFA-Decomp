// Function: FUN_80020958
// Entry: 80020958
// Size: 724 bytes

void FUN_80020958(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  FUN_8002b9ec();
  DAT_803dca42 = 0;
  FUN_8001b684();
  if (DAT_803dca3a == '\0') {
    (**(code **)(*DAT_803dca50 + 0x54))();
  }
  FUN_8001485c();
  FUN_801021a4();
  FUN_80014e70(0);
  FUN_8002e628(DAT_803dca3c);
  if (DAT_803dca3a == '\0') {
    FUN_8005c7ec(0);
    (**(code **)(*DAT_803dcaac + 0x70))();
    iVar3 = FUN_8002b9ec();
    iVar1 = DAT_803dcad4 * 0x10;
    iVar2 = DAT_803dcad0 + (uint)DAT_803db410;
    DAT_803dcad0 = iVar2;
    if (iVar3 != 0) {
      *(undefined4 *)(&DAT_8033bfb8 + iVar1) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(&DAT_8033bfbc + iVar1) = *(undefined4 *)(iVar3 + 0x10);
      *(undefined4 *)(&DAT_8033bfc0 + iVar1) = *(undefined4 *)(iVar3 + 0x14);
      *(int *)(&DAT_8033bfc4 + iVar1) = iVar2;
      DAT_803dcad4 = DAT_803dcad4 + 1;
      if (0x3b < DAT_803dcad4) {
        DAT_803dcad4 = 0;
      }
    }
  }
  FUN_8006f400((double)FLOAT_803db414);
  FUN_800147a4();
  FUN_80064c8c();
  FUN_8005649c();
  FUN_80058094();
  FUN_8002e124();
  (**(code **)(*DAT_803dca6c + 0x3c))();
  FUN_800703ac();
  if (DAT_803dca46 == 0) {
    FUN_8005c750(0,0,0,0,0,0);
    (**(code **)(*DAT_803dca90 + 0xc))(0);
    if (DAT_803dca48 == '\0') {
      FUN_8001476c(0,0,0,0);
    }
    (**(code **)(*DAT_803dcabc + 8))();
    if (DAT_803dca48 == '\0') {
      FUN_80015624();
    }
    FUN_80019c24();
  }
  else {
    DAT_803dca46 = DAT_803dca46 + -1;
    if (DAT_803dca46 < 0) {
      DAT_803dca46 = 0;
    }
  }
  if (DAT_803dca42 == 0) {
    if (DAT_803dca44 != '\0') {
      FLOAT_803db420 = FLOAT_803db420 - FLOAT_803db414;
      if (FLOAT_803db420 <= FLOAT_803de7b0) {
        FUN_8000a518(0xc9,0);
        FUN_8000a518(0xd0,0);
        DAT_803dca44 = '\0';
      }
    }
    if (FLOAT_803db420 <= FLOAT_803de7b0) {
      FLOAT_803db420 = FLOAT_803de7b4;
    }
  }
  else {
    if (DAT_803dca44 == '\0') {
      FLOAT_803db420 = FLOAT_803db420 + FLOAT_803db414;
      if (FLOAT_803de7b0 <= FLOAT_803db420) {
        FUN_8000a518(DAT_803dcaf0,1);
        DAT_803dca44 = '\x01';
      }
    }
    if (FLOAT_803de7b0 <= FLOAT_803db420) {
      FLOAT_803db420 = FLOAT_803de7b8;
    }
  }
  FUN_8000f0b8(0);
  DAT_803dca3b = DAT_803dca3b - DAT_803db410;
  if (DAT_803dca3b < '\0') {
    DAT_803dca3b = '\0';
  }
  return;
}

