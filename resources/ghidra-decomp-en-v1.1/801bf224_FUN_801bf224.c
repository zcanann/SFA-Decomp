// Function: FUN_801bf224
// Entry: 801bf224
// Size: 496 bytes

void FUN_801bf224(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,int param_11)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  uVar2 = 6;
  if (param_11 != 0) {
    uVar2 = 7;
  }
  iVar3 = *DAT_803dd738;
  (**(code **)(iVar3 + 0x58))((double)FLOAT_803e5964,param_9,param_10,iVar4,2,2,0x102);
  *(code **)(param_9 + 0xbc) = FUN_801bea00;
  (**(code **)(*DAT_803dd70c + 0x14))(param_9,iVar4,0);
  *(undefined2 *)(iVar4 + 0x270) = 0;
  uVar1 = FUN_80020078(0x20c);
  DAT_803de814 = (char)uVar1;
  if (DAT_803de814 < '\x03') {
    *(char *)(iVar4 + 0x354) = '\x03' - DAT_803de814;
  }
  else {
    *(char *)(iVar4 + 0x354) = '\a' - DAT_803de814;
  }
  FLOAT_803de824 = FLOAT_803e5928;
  FLOAT_803de820 = FLOAT_803e5928;
  FLOAT_803de818 = FLOAT_803e5928;
  FLOAT_803de81c = FLOAT_803e5934;
  DAT_803de810 = FUN_8001f58c(0,'\x01');
  if (DAT_803de810 != (int *)0x0) {
    FUN_8001dbf0((int)DAT_803de810,2);
    FUN_8001dbb4((int)DAT_803de810,0xff,0,0,0x7f);
    FUN_8001dadc((int)DAT_803de810,0xff,0,0,0x7f);
    dVar5 = (double)FLOAT_803e5938;
    FUN_8001dcfc((double)FLOAT_803e5934,dVar5,(int)DAT_803de810);
    FUN_8001dc18((int)DAT_803de810,1);
    FUN_8001dc30((double)FLOAT_803e5928,(int)DAT_803de810,'\x01');
    FUN_8001d7d8((double)FLOAT_803e5938,(int)DAT_803de810);
    FUN_8001db7c((int)DAT_803de810,0xff,0x7f,0,0x40);
    FUN_8001daa4((int)DAT_803de810,0xff,0x7f,0,0x40);
    FUN_8001d6e4((int)DAT_803de810,2,0x3c);
    FUN_8001de04((int)DAT_803de810,1);
    FUN_8001d7f4((double)FLOAT_803e5938,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,
                 DAT_803de810,0,0xff,0,0,0x7f,uVar2,iVar3);
  }
  return;
}

