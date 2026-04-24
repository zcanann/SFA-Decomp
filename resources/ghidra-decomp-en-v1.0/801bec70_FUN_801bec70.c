// Function: FUN_801bec70
// Entry: 801bec70
// Size: 496 bytes

void FUN_801bec70(int param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = 6;
  if (param_3 != 0) {
    uVar1 = 7;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))((double)FLOAT_803e4ccc,param_1,param_2,iVar2,2,2,0x102,uVar1);
  *(code **)(param_1 + 0xbc) = FUN_801be44c;
  (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar2,0);
  *(undefined2 *)(iVar2 + 0x270) = 0;
  DAT_803ddb94 = FUN_8001ffb4(0x20c);
  if (DAT_803ddb94 < '\x03') {
    *(char *)(iVar2 + 0x354) = '\x03' - DAT_803ddb94;
  }
  else {
    *(char *)(iVar2 + 0x354) = '\a' - DAT_803ddb94;
  }
  FLOAT_803ddba4 = FLOAT_803e4c90;
  FLOAT_803ddba0 = FLOAT_803e4c90;
  FLOAT_803ddb98 = FLOAT_803e4c90;
  FLOAT_803ddb9c = FLOAT_803e4c9c;
  DAT_803ddb90 = FUN_8001f4c8(0,1);
  if (DAT_803ddb90 != 0) {
    FUN_8001db2c(DAT_803ddb90,2);
    FUN_8001daf0(DAT_803ddb90,0xff,0,0,0x7f);
    FUN_8001da18(DAT_803ddb90,0xff,0,0,0x7f);
    FUN_8001dc38((double)FLOAT_803e4c9c,(double)FLOAT_803e4ca0,DAT_803ddb90);
    FUN_8001db54(DAT_803ddb90,1);
    FUN_8001db6c((double)FLOAT_803e4c90,DAT_803ddb90,1);
    FUN_8001d714((double)FLOAT_803e4ca0,DAT_803ddb90);
    FUN_8001dab8(DAT_803ddb90,0xff,0x7f,0,0x40);
    FUN_8001d9e0(DAT_803ddb90,0xff,0x7f,0,0x40);
    FUN_8001d620(DAT_803ddb90,2,0x3c);
    FUN_8001dd40(DAT_803ddb90,1);
    FUN_8001d730((double)FLOAT_803e4ca0,DAT_803ddb90,0,0xff,0,0,0x7f);
  }
  return;
}

