// Function: FUN_801f6b84
// Entry: 801f6b84
// Size: 516 bytes

void FUN_801f6b84(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  char cVar1;
  short sVar2;
  byte bVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  undefined8 uVar5;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  sVar2 = *(short *)(iVar4 + 8);
  if (sVar2 == 0x21) {
    FUN_800201ac(0xd1b,1);
  }
  else if (sVar2 == 1) {
    bVar3 = FUN_80089094(0);
    cVar1 = *(char *)(iVar4 + 0xf);
    if ((cVar1 == '\0') || (bVar3 != 0)) {
      if ((cVar1 == '\0') && (bVar3 != 0)) {
        uVar5 = FUN_80008b74(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                             0x217,0,in_r7,in_r8,in_r9,in_r10);
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             param_9,0x216,0,in_r7,in_r8,in_r9,in_r10);
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             param_9,0x84,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                     0x8a,0,in_r7,in_r8,in_r9,in_r10);
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),4,0);
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),10,1);
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0xb,1);
      }
    }
    else {
      uVar5 = FUN_80008b74(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x22d
                           ,0,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x22c,0,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_9,0x229,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x22a,0,in_r7,in_r8,in_r9,in_r10);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),4,1);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),10,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0xb,0);
    }
  }
  return;
}

