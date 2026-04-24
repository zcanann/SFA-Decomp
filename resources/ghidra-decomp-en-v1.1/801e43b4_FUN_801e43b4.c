// Function: FUN_801e43b4
// Entry: 801e43b4
// Size: 312 bytes

void FUN_801e43b4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  short sVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  dVar5 = (double)*(float *)(iVar3 + 0x1c);
  dVar4 = (double)FLOAT_803e654c;
  if (dVar5 <= dVar4) {
    iVar2 = *(int *)(*(int *)(param_9 + 0x54) + 0x50);
    if ((((iVar2 != 0) && (sVar1 = *(short *)(iVar2 + 0x46), sVar1 != 0x119)) && (sVar1 != 0x113))
       && (dVar4 == dVar5)) {
      FUN_8000bb38(param_9,0x31d);
      *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
      *(float *)(iVar3 + 0x1c) = FLOAT_803e6550;
      *(undefined *)(param_9 + 0x36) = 0x19;
      iVar3 = 0x32;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0xa7,0,1,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      iVar3 = 10;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0xab,0,1,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  else {
    *(float *)(iVar3 + 0x1c) = (float)(dVar5 - (double)FLOAT_803dc074);
    if ((double)*(float *)(iVar3 + 0x1c) <= dVar4) {
      FUN_8002cc9c(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return;
}

