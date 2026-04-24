// Function: FUN_80143468
// Entry: 80143468
// Size: 304 bytes

undefined4
FUN_80143468(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int *param_10,int param_11,undefined4 param_12,byte param_13,uint param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  char cVar3;
  bool bVar4;
  uint uVar2;
  
  iVar1 = FUN_80144994(param_9,param_10);
  if ((iVar1 == 0) &&
     (cVar3 = FUN_8013b6f0((double)FLOAT_803e30a8,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                           param_16), cVar3 != '\x01')) {
    if (param_10[0x1ec] == 0) {
      uVar2 = FUN_80022264(0,6);
      if (((int)uVar2 < 5) && (-1 < (int)uVar2)) {
        FUN_8014482c(param_9,(int)param_10);
      }
      else {
        FUN_80144548();
      }
    }
    else {
      iVar1 = *(int *)(param_9 + 0xb8);
      if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
          (bVar4 = FUN_8000b598(param_9,0x10), !bVar4)))) {
        FUN_800394f0(param_9,iVar1 + 0x3a8,0x357,0,0xffffffff,0);
      }
      FUN_8013a778((double)FLOAT_803e31ac,param_9,0x26,0);
      *(undefined *)((int)param_10 + 10) = 5;
    }
  }
  return 1;
}

