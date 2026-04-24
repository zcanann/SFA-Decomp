// Function: FUN_8007e7a0
// Entry: 8007e7a0
// Size: 392 bytes

void FUN_8007e7a0(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char cVar3;
  uint uVar1;
  undefined4 uVar2;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  undefined4 local_28;
  int local_24 [9];
  
  cVar3 = FUN_80286840();
  FUN_8001746c(0);
  iVar5 = 0;
  do {
    FUN_80014f6c();
    FUN_800235b0();
    FUN_8004a9e4();
    uVar1 = FUN_8001fe4c(local_24);
    if ((uVar1 & 0xff) == 0) {
      local_28 = DAT_803dc368;
      uVar2 = FUN_8006c8b8();
      FUN_80076ef4(uVar2,0,0,&local_28,0x200,0);
    }
    else {
      (**(code **)(*DAT_803dd6cc + 4))(0,0,0);
      param_2 = (double)FLOAT_803dfc18;
      FUN_8007668c(param_2,param_2,0x280,0x1e0);
      iVar6 = 0;
      for (iVar4 = 0; iVar4 < (int)(uVar1 & 0xff); iVar4 = iVar4 + 1) {
        FUN_8003b9ec(*(int *)(local_24[0] + iVar6));
        iVar6 = iVar6 + 4;
      }
      FUN_80014798();
    }
    uVar7 = FUN_80019940(0xff,0xff,0xff,0xff);
    if (cVar3 == '\x01') {
      uVar7 = FUN_80016848(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x323,0,200
                          );
    }
    else if (cVar3 == '\x02') {
      uVar7 = FUN_80016848(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x573,0,200
                          );
    }
    else {
      uVar7 = FUN_80016848(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x56c,0,200
                          );
    }
    FUN_80019c5c(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_8004a5b8('\x01');
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x3c);
  FUN_8028688c();
  return;
}

