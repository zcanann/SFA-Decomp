// Function: FUN_8019eae4
// Entry: 8019eae4
// Size: 352 bytes

void FUN_8019eae4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10,int param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  uVar3 = 0x28;
  uVar4 = 0;
  uVar5 = 3;
  FUN_8003aebc(param_9,param_10,param_11 + 0x3c,0x28,0,3);
  iVar2 = FUN_800386e0(param_9,param_10,(float *)0x0);
  sVar1 = (short)(iVar2 >> 3);
  *param_9 = *param_9 + sVar1;
  if (param_12 != 0) {
    if ((sVar1 < -199) || (199 < sVar1)) {
      if (*(int *)(param_11 + 0xc0) == 0) {
        *(undefined4 *)(param_11 + 0xc0) = 1;
        FUN_8003042c((double)FLOAT_803e4eb0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,9,0,uVar3,uVar4,uVar5,param_15,param_16);
      }
      else {
        iVar2 = (int)sVar1;
        if (iVar2 < 1) {
          sVar1 = (short)(-iVar2 >> 2);
        }
        else {
          sVar1 = (short)(iVar2 >> 2);
        }
        FUN_8002fb40((double)((float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000) -
                                     DOUBLE_803e4eb8) / FLOAT_803e4ed8),(double)FLOAT_803dc074);
      }
    }
    else if (*(int *)(param_11 + 0xc0) == 0) {
      FUN_8002fb40((double)FLOAT_803e4ed4,(double)FLOAT_803dc074);
    }
    else {
      *(undefined4 *)(param_11 + 0xc0) = 0;
      FUN_8003042c((double)FLOAT_803e4eb0,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0,0,uVar3,uVar4,uVar5,param_15,param_16);
    }
  }
  return;
}

