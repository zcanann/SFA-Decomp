// Function: FUN_80125528
// Entry: 80125528
// Size: 480 bytes

void FUN_80125528(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int extraout_r4;
  int extraout_r4_00;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar6;
  int local_18 [3];
  
  iVar1 = FUN_8002bac4();
  iVar2 = FUN_8002ba84();
  uVar4 = 0x280;
  uVar5 = 0x1e0;
  FUN_8025da88(0,0,0x280,0x1e0);
  uVar6 = FUN_8012146c(param_9,&DAT_803a9ff8);
  if (iVar2 == 0) {
    DAT_803de3b8 = 0;
    DAT_803de3bc = 0;
  }
  else {
    DAT_803de3b8 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x24))(iVar2);
    uVar6 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2);
    DAT_803de3bc = (undefined4)((ulonglong)uVar6 >> 0x20);
  }
  FUN_801200f0((int)((ulonglong)uVar6 >> 0x20),(int)uVar6,uVar4,uVar5,in_r7,in_r8,in_r9,in_r10);
  iVar3 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if ((((iVar3 != 0x44) && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) && (DAT_803de400 == '\0'))
     && ((iVar2 != 0 && (iVar1 = FUN_80020800(), iVar1 == 0)))) {
    iVar3 = **(int **)(iVar2 + 0x68);
    uVar6 = (**(code **)(iVar3 + 0x48))(iVar2,local_18);
    iVar1 = extraout_r4;
    if ((DAT_803de4b4 != 0) && (iVar1 = (int)DAT_803de4b0, iVar1 != local_18[0])) {
      uVar6 = FUN_80054484();
      DAT_803de4b0 = -1;
      DAT_803de4b4 = 0;
      iVar1 = extraout_r4_00;
    }
    if (((DAT_803de4b4 == 0) && (-1 < local_18[0])) &&
       (*(short *)(&DAT_8031c268 + local_18[0] * 2) != -1)) {
      DAT_803de4b4 = FUN_80054ed0(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  (int)*(short *)(&DAT_8031c268 + local_18[0] * 2),iVar1,iVar3,uVar5
                                  ,in_r7,in_r8,in_r9,in_r10);
    }
    DAT_803de4b0 = (short)local_18[0];
    if (DAT_803de4b4 != 0) {
      FUN_80077318((double)FLOAT_803e2c98,(double)FLOAT_803e2cb8,DAT_803a9684,0xff,0x100);
      FUN_80077318((double)FLOAT_803e2c98,(double)FLOAT_803e2cbc,DAT_803de4b4,0xff,0x80);
    }
  }
  return;
}

