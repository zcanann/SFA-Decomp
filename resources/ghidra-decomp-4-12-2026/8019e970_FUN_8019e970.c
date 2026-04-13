// Function: FUN_8019e970
// Entry: 8019e970
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x8019eac4) */
/* WARNING: Removing unreachable block (ram,0x8019e980) */

undefined4
FUN_8019e970(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  if ((*(short *)(param_9 + 0xa0) != 5) && (*(short *)(param_9 + 0xa0) != 0xd)) {
    FUN_8003042c((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
  }
  if ((*(short *)(param_9 + 0xa0) == 5) && (FLOAT_803e4ec4 < *(float *)(param_9 + 0x28))) {
    FUN_8003042c((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
  }
  if ((*(short *)(param_9 + 0xa0) == 0xd) && (*(float *)(param_9 + 0x28) < FLOAT_803e4eb0)) {
    FUN_8003042c((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,5,0,param_12,param_13,param_14,param_15,param_16);
  }
  dVar2 = (double)((*(float *)(param_9 + 0x28) * FLOAT_803dcab4 + FLOAT_803e4ec8) * FLOAT_803e4ecc);
  if (dVar2 < (double)FLOAT_803e4eb0) {
    dVar2 = (double)FLOAT_803e4eb0;
  }
  if ((double)FLOAT_803e4ecc < dVar2) {
    dVar2 = (double)FLOAT_803e4ecc;
  }
  if (*(short *)(param_9 + 0xa0) == 0xd) {
    if (*(float *)(param_9 + 0x98) <= FLOAT_803e4ecc) {
      *(byte *)(iVar1 + 0x244) = *(byte *)(iVar1 + 0x244) & 0xbf;
    }
    else if ((*(byte *)(iVar1 + 0x244) >> 6 & 1) == 0) {
      FUN_8000bb38(param_9,0x334);
      *(byte *)(iVar1 + 0x244) = *(byte *)(iVar1 + 0x244) & 0xbf | 0x40;
    }
  }
  FUN_8002fb40(dVar2,(double)FLOAT_803dc074);
  return 1;
}

