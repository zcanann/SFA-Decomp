// Function: FUN_80013590
// Entry: 80013590
// Size: 484 bytes

void FUN_80013590(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int *piVar1;
  int iVar2;
  
  FUN_8001f82c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803dd560,0x35,
               param_11,param_12,param_13,param_14,param_15,param_16);
  iVar2 = 0;
  for (piVar1 = DAT_803dd560; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar2 = iVar2 + 1;
  }
  DAT_803dd548 = iVar2 + -1;
  DAT_803dd558 = FUN_80023d8c(0x280,0x10);
  DAT_8033945c = 0;
  DAT_80339430 = 0xfffffffe;
  DAT_80339418 = 0x40000000;
  DAT_803dd550 = 0;
  DAT_80339400 = 0;
  DAT_80339402 = 0;
  DAT_80339460 = 0;
  DAT_80339434 = 0xfffffffe;
  DAT_8033941c = 0x40000000;
  uRam803dd551 = 0;
  DAT_80339404 = 0;
  DAT_80339406 = 0;
  DAT_80339464 = 0;
  DAT_80339438 = 0xfffffffe;
  DAT_80339420 = 0x40000000;
  uRam803dd552 = 0;
  DAT_80339408 = 0;
  DAT_8033940a = 0;
  DAT_80339468 = 0;
  DAT_8033943c = 0xfffffffe;
  DAT_80339424 = 0x40000000;
  uRam803dd553 = 0;
  DAT_8033940c = 0;
  DAT_8033940e = 0;
  DAT_8033946c = 0;
  DAT_80339440 = 0xfffffffe;
  DAT_80339428 = 0x40000000;
  uRam803dd554 = 0;
  DAT_80339410 = 0;
  DAT_80339412 = 0;
  DAT_80339470 = 0;
  DAT_80339444 = 0xfffffffe;
  DAT_8033942c = 0x40000000;
  uRam803dd555 = 0;
  DAT_80339414 = 0;
  DAT_80339416 = 0;
  DAT_803dd54c = 0;
  DAT_803dd55c = DAT_803dd558;
  DAT_803dd540 = FUN_80054e14(0x40,0x40,4,'\0',0,0,0,0,0);
  uRam803dd544 = FUN_80054e14(0x40,0x40,4,'\0',0,0,0,0,0);
  DAT_803dd538 = FUN_80054e14(0x10,0x10,4,'\0',0,0,0,0,0);
  uRam803dd53c = FUN_80054e14(0x10,0x10,4,'\0',0,0,0,0,0);
  return;
}

