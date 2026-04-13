// Function: FUN_801a6d2c
// Entry: 801a6d2c
// Size: 972 bytes

void FUN_801a6d2c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar4;
  undefined8 uVar5;
  
  iVar1 = FUN_8002bac4();
  uVar2 = FUN_8002bac4();
  dVar4 = (double)FLOAT_803de7a8;
  if ((double)FLOAT_803e5158 < dVar4) {
    FUN_800168a8(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x34f);
    FLOAT_803de7a8 = FLOAT_803de7a8 - FLOAT_803dc074;
    dVar4 = (double)FLOAT_803de7a8;
    if (dVar4 < (double)FLOAT_803e5158) {
      FLOAT_803de7a8 = FLOAT_803e5158;
    }
  }
  if (*(int *)(param_9 + 0xf4) != 0) {
    FUN_80088a84(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
    uVar3 = FUN_80020078(0xd47);
    if (uVar3 == 0) {
      uVar3 = FUN_80020078(0xf33);
      if (uVar3 == 0) {
        param_2 = (double)*(float *)(iVar1 + 0x14);
        iVar1 = FUN_8005b128();
        if (iVar1 == 0x12) {
          uVar5 = FUN_80088f20(7,'\0');
          if (*(int *)(param_9 + 0xf4) == 2) {
            uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
            uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x138,0,in_r7,in_r8,in_r9,in_r10);
            FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x139,0,in_r7,in_r8,in_r9,in_r10);
          }
          else {
            uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
            uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 param_9,uVar2,0x138,0,in_r7,in_r8,in_r9,in_r10);
            FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x139,0,in_r7,in_r8,in_r9,in_r10);
          }
          *(undefined4 *)(param_9 + 0xf8) = 0;
        }
      }
      else {
        uVar5 = FUN_80088f20(7,'\x01');
        if (*(int *)(param_9 + 0xf4) == 2) {
          uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
          uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x10c,0,in_r7,in_r8,in_r9,in_r10);
          FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                       0x10d,0,in_r7,in_r8,in_r9,in_r10);
        }
        else {
          uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
          uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
                               ,uVar2,0x10c,0,in_r7,in_r8,in_r9,in_r10);
          FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                       0x10d,0,in_r7,in_r8,in_r9,in_r10);
        }
        *(undefined4 *)(param_9 + 0xf8) = 1;
      }
    }
    else {
      uVar5 = FUN_80088f20(7,'\x01');
      if (*(int *)(param_9 + 0xf4) == 2) {
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x234,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                     0x235,0,in_r7,in_r8,in_r9,in_r10);
      }
      else {
        uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
        uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             uVar2,0x234,0,in_r7,in_r8,in_r9,in_r10);
        FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,
                     0x235,0,in_r7,in_r8,in_r9,in_r10);
      }
      *(undefined4 *)(param_9 + 0xf8) = 0;
    }
    FUN_8000a538((int *)0x31,1);
    *(undefined4 *)(param_9 + 0xf4) = 0;
  }
  if ((*(int *)(param_9 + 0xf8) == 0) || (uVar3 = FUN_80020078(0xf33), uVar3 != 0)) {
    if ((*(int *)(param_9 + 0xf8) == 0) && (uVar3 = FUN_80020078(0xf33), uVar3 != 0)) {
      uVar5 = FUN_80088f20(7,'\x01');
      uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           uVar2,0x13a,0,in_r7,in_r8,in_r9,in_r10);
      uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           uVar2,0x10c,0,in_r7,in_r8,in_r9,in_r10);
      FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,0x10d
                   ,0,in_r7,in_r8,in_r9,in_r10);
      *(undefined4 *)(param_9 + 0xf8) = 1;
    }
  }
  else {
    uVar5 = FUN_80088f20(7,'\0');
    uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x13a,0,in_r7,in_r8,in_r9,in_r10);
    uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2
                         ,0x138,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,uVar2,0x139,0
                 ,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(param_9 + 0xf8) = 0;
  }
  FUN_801d84c4(&DAT_803de7ac,1,-1,-1,0x389,(int *)0xd5);
  FUN_801d84c4(&DAT_803de7ac,2,-1,-1,0xcbb,(int *)0xc4);
  return;
}

