// Function: FUN_80204098
// Entry: 80204098
// Size: 648 bytes

void FUN_80204098(void)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined2 uVar4;
  char cVar5;
  short sVar6;
  undefined2 *puVar7;
  undefined2 *puVar8;
  
  iVar1 = FUN_802860dc();
  puVar8 = *(undefined2 **)(iVar1 + 0xb8);
  uVar2 = FUN_8002b9ec();
  if (DAT_803dc183 != '\0') {
    FUN_800200e8(0x2d,1);
    FUN_800200e8(0x1d7,1);
    puVar7 = &DAT_80329848;
    for (sVar6 = 0; sVar6 < 9; sVar6 = sVar6 + 1) {
      uVar4 = FUN_800221a0(1,4);
      *puVar7 = uVar4;
      puVar7 = puVar7 + 1;
    }
    FUN_800200e8(0x5e4,0);
    *puVar8 = 0;
    DAT_803dc183 = '\0';
  }
  iVar3 = FUN_8001ffb4(0x5e3);
  if (((iVar3 == 0) && (iVar3 = FUN_8001ffb4(0x5e0), iVar3 != 0)) &&
     (iVar3 = FUN_8001ffb4(0x5e1), iVar3 != 0)) {
    FUN_8000bb18(iVar1,0x7a);
    FUN_800200e8(0x5e3,1);
  }
  iVar3 = FUN_8001ffb4(0x792);
  if (((iVar3 == 0) && (iVar3 = FUN_8001ffb4(0xb8c), iVar3 != 0)) &&
     (iVar3 = FUN_8001ffb4(0xb8c), iVar3 != 0)) {
    FUN_8000bb18(iVar1,0x7a);
    FUN_800200e8(0x792,1);
  }
  iVar3 = FUN_8001ffb4(0xe58);
  if (iVar3 == 0) {
    iVar3 = FUN_8001ffb4(0x635);
    if ((iVar3 == 0) || (*(char *)(puVar8 + 3) != '\0')) {
      iVar3 = FUN_8001ffb4(0x635);
      if ((iVar3 == 0) && (*(char *)(puVar8 + 3) == '\x01')) {
        *(undefined *)(puVar8 + 3) = 0;
        FUN_800200e8(0x5e4,0);
      }
    }
    else {
      FUN_8000bb18(0,0x1c4);
      puVar7 = &DAT_80329848;
      for (sVar6 = 0; sVar6 < 9; sVar6 = sVar6 + 1) {
        uVar4 = FUN_800221a0(1,4);
        *puVar7 = uVar4;
        puVar7 = puVar7 + 1;
      }
      FUN_800200e8(0x5e4,1);
      *(undefined *)(puVar8 + 3) = 1;
    }
    iVar3 = FUN_8001ffb4(0x5e5);
    if (iVar3 != 0) {
      *puVar8 = 300;
      FUN_800378c4(uVar2,0x60005,iVar1,0);
    }
  }
  iVar3 = FUN_8001ffb4(0x7a1);
  if ((iVar3 != 0) &&
     (cVar5 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(iVar1 + 0xac),6), cVar5 == '\0')) {
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(iVar1 + 0xac),6,1);
  }
  FUN_80286128();
  return;
}

