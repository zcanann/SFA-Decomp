// Function: FUN_8023113c
// Entry: 8023113c
// Size: 592 bytes

void FUN_8023113c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  char cVar4;
  int iVar2;
  uint uVar3;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  undefined8 uVar8;
  undefined8 extraout_f1;
  
  iVar7 = *(int *)(param_9 + 0xb8);
  iVar1 = FUN_8022de2c();
  if (*(char *)(iVar7 + 0x18) == '\0') {
    FUN_8008999c(7,1,0);
    if (*(char *)(iVar7 + 0x1b) == '\0') {
      uVar5 = 0;
      uVar6 = 0;
      FUN_8008986c(7,0x96,100,0xf0,0,0);
    }
    else {
      uVar5 = 0x69;
      uVar6 = 0x40;
      FUN_8008986c(7,0xaa,0x78,0xff,0x69,0x40);
    }
    param_2 = (double)FLOAT_803e7d7c;
    param_3 = (double)FLOAT_803e7d78;
    uVar8 = FUN_80089734(param_2,param_2,param_3,7);
    uVar8 = FUN_80008cbc(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x21f,0,
                         uVar5,uVar6,in_r9,in_r10);
    FUN_80008cbc(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x22b,0,uVar5,
                 uVar6,in_r9,in_r10);
    FUN_8005d024(0);
    *(undefined *)(iVar7 + 0x18) = 1;
    FUN_8005cf74(0);
  }
  if (*(char *)(iVar7 + 0x19) == '\0') {
    if (*(char *)(iVar7 + 0x1b) == '\0') {
      cVar4 = FUN_8000cfc0();
      if (cVar4 == '\0') {
        FUN_8000d220(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      uVar5 = 0;
    }
    else {
      uVar5 = 3;
    }
    (**(code **)(*DAT_803dd6d4 + 0x48))(uVar5,param_9,0xffffffff);
    *(undefined *)(iVar7 + 0x19) = 1;
    FUN_800201ac(0x9d6,0);
    FUN_800201ac(0x9d8,0);
    FUN_800201ac(0x9d7,0);
  }
  if ((((*(char *)(iVar7 + 0x1a) == '\0') &&
       (iVar2 = FUN_80059460(), FLOAT_803e7d80 < *(float *)(iVar1 + 0x14) - *(float *)(iVar2 + 0x28)
       )) && (uVar3 = FUN_8022de14(iVar1), uVar3 == 0)) && (iVar2 = FUN_8022ddd4(iVar1), iVar2 == 0)
     ) {
    FUN_8011f638(2);
    (**(code **)(*DAT_803dd6d4 + 0x7c))(*(undefined2 *)(iVar7 + 0x20),0,0);
    iVar2 = FUN_8022dbcc(iVar1);
    iVar1 = FUN_8022dbd8(iVar1);
    if (iVar1 < iVar2) {
      FUN_800201ac(0x9d7,1);
    }
    else {
      FUN_800201ac(0x9d8,1);
    }
    *(undefined *)(iVar7 + 0x1a) = 1;
    FUN_8000a538((int *)0x2,0);
    FUN_8000a538((int *)0xf3,0);
  }
  return;
}

