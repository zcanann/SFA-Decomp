// Function: FUN_80142d9c
// Entry: 80142d9c
// Size: 344 bytes

undefined4
FUN_80142d9c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10,undefined4 param_11,undefined4 param_12,byte param_13,uint param_14,
            undefined4 param_15,undefined4 param_16)

{
  bool bVar2;
  char cVar3;
  uint uVar1;
  float *pfVar4;
  int iVar5;
  double dVar6;
  float local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  pfVar4 = &local_28;
  FUN_80039608(*(int *)(param_10 + 0x24),0,pfVar4);
  dVar6 = FUN_80021730(&local_28,(float *)(param_10 + 0x72c));
  if ((double)FLOAT_803e30b4 < dVar6) {
    *(float *)(param_10 + 0x72c) = local_28;
    *(undefined4 *)(param_10 + 0x730) = local_24;
    *(undefined4 *)(param_10 + 0x734) = local_20;
  }
  if ((*(byte *)(param_10 + 0x728) >> 5 & 1) == 0) {
    cVar3 = FUN_8013b6f0((double)FLOAT_803e3158,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,(int)pfVar4,param_12,param_13,param_14,param_15,
                         param_16);
    if (cVar3 != '\x01') {
      *(byte *)(param_10 + 0x728) = *(byte *)(param_10 + 0x728) & 0xdf | 0x20;
      uVar1 = FUN_80022264(0x35e,0x35f);
      iVar5 = *(int *)(param_9 + 0xb8);
      if (((*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
          (bVar2 = FUN_8000b598(param_9,0x10), !bVar2)))) {
        FUN_800394f0(param_9,iVar5 + 0x3a8,(ushort)uVar1,0x500,0xffffffff,0);
      }
      return 0;
    }
  }
  else {
    bVar2 = FUN_8000b598(param_9,0x10);
    if (bVar2) {
      return 0;
    }
    FUN_8014482c(param_9,param_10);
  }
  return 1;
}

