// Function: FUN_80204958
// Entry: 80204958
// Size: 460 bytes

void FUN_80204958(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar4;
  undefined2 *puVar5;
  undefined2 *puVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  uVar1 = FUN_80286840();
  puVar6 = *(undefined2 **)(uVar1 + 0xb8);
  uVar7 = extraout_f1;
  iVar2 = FUN_8002bac4();
  if (DAT_803dcdea != '\0') {
    puVar5 = &DAT_8032a488;
    DAT_8032a494 = 0;
    DAT_8032a496 = 0;
    DAT_8032a498 = 0;
    for (sVar4 = 0; sVar4 < 6; sVar4 = sVar4 + 1) {
      uVar3 = FUN_80022264(1,4);
      *puVar5 = (short)uVar3;
      puVar5 = puVar5 + 1;
    }
    uVar7 = FUN_800201ac(0x5e4,0);
    *puVar6 = 0;
    DAT_803dcdea = '\0';
  }
  uVar3 = FUN_80020078(0x5e3);
  if (((uVar3 == 0) && (uVar3 = FUN_80020078(0x5e0), uVar3 != 0)) &&
     (uVar3 = FUN_80020078(0x5e1), uVar3 != 0)) {
    uVar7 = FUN_800201ac(0x5e3,1);
  }
  uVar3 = FUN_80020078(0xe57);
  if (uVar3 == 0) {
    uVar3 = FUN_80020078(0x635);
    if ((uVar3 == 0) || (*(char *)(puVar6 + 3) != '\0')) {
      uVar3 = FUN_80020078(0x635);
      if ((uVar3 == 0) && (*(char *)(puVar6 + 3) == '\x01')) {
        *(undefined *)(puVar6 + 3) = 0;
        uVar7 = FUN_800201ac(0x5e4,0);
      }
    }
    else {
      FUN_8000bb38(0,0x447);
      puVar5 = &DAT_8032a488;
      for (sVar4 = 0; sVar4 < 6; sVar4 = sVar4 + 1) {
        uVar3 = FUN_80022264(1,4);
        *puVar5 = (short)uVar3;
        puVar5 = puVar5 + 1;
      }
      uVar7 = FUN_800201ac(0x5e4,1);
      *(undefined *)(puVar6 + 3) = 1;
    }
    uVar3 = FUN_80020078(0x5e5);
    if (uVar3 != 0) {
      *puVar6 = 300;
      FUN_800379bc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x60005,uVar1
                   ,1,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_8028688c();
  return;
}

