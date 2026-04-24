// Function: FUN_80204320
// Entry: 80204320
// Size: 460 bytes

void FUN_80204320(void)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined2 uVar4;
  short sVar5;
  undefined2 *puVar6;
  undefined2 *puVar7;
  
  iVar1 = FUN_802860dc();
  puVar7 = *(undefined2 **)(iVar1 + 0xb8);
  uVar2 = FUN_8002b9ec();
  if (DAT_803dc182 != '\0') {
    puVar6 = &DAT_80329848;
    DAT_80329854 = 0;
    DAT_80329856 = 0;
    DAT_80329858 = 0;
    for (sVar5 = 0; sVar5 < 6; sVar5 = sVar5 + 1) {
      uVar4 = FUN_800221a0(1,4);
      *puVar6 = uVar4;
      puVar6 = puVar6 + 1;
    }
    FUN_800200e8(0x5e4,0);
    *puVar7 = 0;
    DAT_803dc182 = '\0';
  }
  iVar3 = FUN_8001ffb4(0x5e3);
  if (((iVar3 == 0) && (iVar3 = FUN_8001ffb4(0x5e0), iVar3 != 0)) &&
     (iVar3 = FUN_8001ffb4(0x5e1), iVar3 != 0)) {
    FUN_800200e8(0x5e3,1);
  }
  iVar3 = FUN_8001ffb4(0xe57);
  if (iVar3 == 0) {
    iVar3 = FUN_8001ffb4(0x635);
    if ((iVar3 == 0) || (*(char *)(puVar7 + 3) != '\0')) {
      iVar3 = FUN_8001ffb4(0x635);
      if ((iVar3 == 0) && (*(char *)(puVar7 + 3) == '\x01')) {
        *(undefined *)(puVar7 + 3) = 0;
        FUN_800200e8(0x5e4,0);
      }
    }
    else {
      FUN_8000bb18(0,0x447);
      puVar6 = &DAT_80329848;
      for (sVar5 = 0; sVar5 < 6; sVar5 = sVar5 + 1) {
        uVar4 = FUN_800221a0(1,4);
        *puVar6 = uVar4;
        puVar6 = puVar6 + 1;
      }
      FUN_800200e8(0x5e4,1);
      *(undefined *)(puVar7 + 3) = 1;
    }
    iVar3 = FUN_8001ffb4(0x5e5);
    if (iVar3 != 0) {
      *puVar7 = 300;
      FUN_800378c4(uVar2,0x60005,iVar1,1);
    }
  }
  FUN_80286128();
  return;
}

