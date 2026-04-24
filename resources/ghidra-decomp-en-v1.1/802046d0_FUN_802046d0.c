// Function: FUN_802046d0
// Entry: 802046d0
// Size: 648 bytes

void FUN_802046d0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  char cVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar5;
  undefined2 *puVar6;
  undefined2 *puVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  uVar1 = FUN_80286840();
  puVar7 = *(undefined2 **)(uVar1 + 0xb8);
  uVar8 = extraout_f1;
  iVar2 = FUN_8002bac4();
  if (DAT_803dcdeb != '\0') {
    FUN_800201ac(0x2d,1);
    FUN_800201ac(0x1d7,1);
    puVar6 = &DAT_8032a488;
    for (sVar5 = 0; sVar5 < 9; sVar5 = sVar5 + 1) {
      uVar3 = FUN_80022264(1,4);
      *puVar6 = (short)uVar3;
      puVar6 = puVar6 + 1;
    }
    uVar8 = FUN_800201ac(0x5e4,0);
    *puVar7 = 0;
    DAT_803dcdeb = '\0';
  }
  uVar3 = FUN_80020078(0x5e3);
  if (((uVar3 == 0) && (uVar3 = FUN_80020078(0x5e0), uVar3 != 0)) &&
     (uVar3 = FUN_80020078(0x5e1), uVar3 != 0)) {
    FUN_8000bb38(uVar1,0x7a);
    uVar8 = FUN_800201ac(0x5e3,1);
  }
  uVar3 = FUN_80020078(0x792);
  if (((uVar3 == 0) && (uVar3 = FUN_80020078(0xb8c), uVar3 != 0)) &&
     (uVar3 = FUN_80020078(0xb8c), uVar3 != 0)) {
    FUN_8000bb38(uVar1,0x7a);
    uVar8 = FUN_800201ac(0x792,1);
  }
  uVar3 = FUN_80020078(0xe58);
  if (uVar3 == 0) {
    uVar3 = FUN_80020078(0x635);
    if ((uVar3 == 0) || (*(char *)(puVar7 + 3) != '\0')) {
      uVar3 = FUN_80020078(0x635);
      if ((uVar3 == 0) && (*(char *)(puVar7 + 3) == '\x01')) {
        *(undefined *)(puVar7 + 3) = 0;
        uVar8 = FUN_800201ac(0x5e4,0);
      }
    }
    else {
      FUN_8000bb38(0,0x1c4);
      puVar6 = &DAT_8032a488;
      for (sVar5 = 0; sVar5 < 9; sVar5 = sVar5 + 1) {
        uVar3 = FUN_80022264(1,4);
        *puVar6 = (short)uVar3;
        puVar6 = puVar6 + 1;
      }
      uVar8 = FUN_800201ac(0x5e4,1);
      *(undefined *)(puVar7 + 3) = 1;
    }
    uVar3 = FUN_80020078(0x5e5);
    if (uVar3 != 0) {
      *puVar7 = 300;
      FUN_800379bc(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x60005,uVar1
                   ,0,in_r7,in_r8,in_r9,in_r10);
    }
  }
  uVar3 = FUN_80020078(0x7a1);
  if ((uVar3 != 0) &&
     (cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(uVar1 + 0xac),6), cVar4 == '\0')) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(uVar1 + 0xac),6,1);
  }
  FUN_8028688c();
  return;
}

