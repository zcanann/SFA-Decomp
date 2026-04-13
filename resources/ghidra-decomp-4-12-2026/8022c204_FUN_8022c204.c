// Function: FUN_8022c204
// Entry: 8022c204
// Size: 396 bytes

void FUN_8022c204(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10)

{
  bool bVar1;
  float fVar2;
  double dVar3;
  undefined8 uVar4;
  double dVar5;
  
  FUN_8022b08c(param_9,param_10);
  fVar2 = FLOAT_803e7b64;
  dVar5 = (double)*(float *)(param_10 + 0x408);
  dVar3 = (double)FLOAT_803e7b64;
  if (dVar3 < dVar5) {
    *(float *)(param_10 + 0x408) = (float)(dVar5 - (double)FLOAT_803dc074);
    if (dVar3 <= (double)*(float *)(param_10 + 0x408)) {
      return;
    }
    *(float *)(param_10 + 0x408) = fVar2;
  }
  bVar1 = false;
  if ((*(ushort *)(param_10 + 0x3f8) & 0x100) != 0) {
    *(float *)(param_10 + 0x414) = *(float *)(param_10 + 0x414) - FLOAT_803dc074;
    dVar3 = (double)*(float *)(param_10 + 0x414);
    if (dVar3 <= (double)FLOAT_803e7b64) {
      bVar1 = true;
    }
  }
  if (((*(ushort *)(param_10 + 0x3f4) & 0x100) != 0) || (bVar1)) {
    *(float *)(param_10 + 0x414) = FLOAT_803e7b9c;
    if (*(char *)(param_10 + 0x404) == '\x02') {
      uVar4 = FUN_8022c05c(dVar3,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_10,0,2,1);
      FUN_8022c05c(uVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,1,2,
                   0);
    }
    else if (*(char *)(param_10 + 0x404) == '\x01') {
      uVar4 = FUN_8022c05c(dVar3,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_10,0,1,1);
      FUN_8022c05c(uVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,1,1,
                   0);
    }
    else {
      FUN_8022c05c(dVar3,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                   (uint)*(byte *)(param_10 + 0x405),0,1);
      *(byte *)(param_10 + 0x405) = *(byte *)(param_10 + 0x405) ^ 1;
    }
    *(float *)(param_10 + 0x408) =
         (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x40c)) - DOUBLE_803e7b80)
    ;
  }
  return;
}

