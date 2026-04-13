// Function: FUN_801e6ab0
// Entry: 801e6ab0
// Size: 372 bytes

void FUN_801e6ab0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar4;
  
  iVar1 = FUN_8002bac4();
  iVar2 = FUN_80296e2c(iVar1);
  if ((iVar2 != 0) && (uVar3 = FUN_80020078(0x18b), uVar3 == 0)) {
    param_1 = FUN_80296454(iVar1,0);
  }
  if (*(int *)(param_9 + 0xf4) == 0) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0,1);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),5,1);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),6,1);
    FUN_800201ac(0x617,1);
    param_1 = FUN_80088f20(7,'\x01');
    *(undefined4 *)(param_9 + 0xf4) = 1;
  }
  uVar3 = FUN_80020078(0xd21);
  if ((uVar3 == 0) || (*(int *)(param_9 + 0xf8) != 0)) {
    uVar3 = FUN_80020078(0xd21);
    if ((uVar3 == 0) && (*(int *)(param_9 + 0xf8) != 0)) {
      *(undefined4 *)(param_9 + 0xf8) = 0;
    }
  }
  else {
    uVar4 = FUN_80088a84(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
    uVar4 = FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0x1c8,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x1cb
                 ,0,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(param_9 + 0xf8) = 1;
  }
  return;
}

