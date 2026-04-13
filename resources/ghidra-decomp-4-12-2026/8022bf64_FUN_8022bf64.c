// Function: FUN_8022bf64
// Entry: 8022bf64
// Size: 244 bytes

void FUN_8022bf64(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)

{
  float fVar1;
  double dVar2;
  undefined8 uVar3;
  double dVar4;
  
  fVar1 = FLOAT_803e7b64;
  if (*(int *)(param_10 + 0x438) == 0) {
    dVar4 = (double)*(float *)(param_10 + 0x440);
    dVar2 = (double)FLOAT_803e7b64;
    if (dVar2 < dVar4) {
      *(float *)(param_10 + 0x440) = (float)(dVar4 - (double)FLOAT_803dc074);
      if (dVar2 <= (double)*(float *)(param_10 + 0x440)) {
        return;
      }
      *(float *)(param_10 + 0x440) = fVar1;
    }
    if ((*(ushort *)(param_10 + 0x3f4) & 0x200) != 0) {
      if (*(char *)(param_10 + 0x43c) == '\x01') {
        uVar3 = FUN_8022be28(dVar2,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                             param_10,0);
        FUN_8022be28(uVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,1)
        ;
      }
      else {
        FUN_8022be28(dVar2,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                     (uint)*(byte *)(param_10 + 0x43d));
        *(byte *)(param_10 + 0x43d) = *(byte *)(param_10 + 0x43d) ^ 1;
      }
      *(float *)(param_10 + 0x440) =
           (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x444)) -
                  DOUBLE_803e7b80);
    }
  }
  return;
}

