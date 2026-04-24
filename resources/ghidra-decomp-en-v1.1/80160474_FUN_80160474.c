// Function: FUN_80160474
// Entry: 80160474
// Size: 440 bytes

void FUN_80160474(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  int iVar1;
  double dVar2;
  
  dVar2 = (double)(float)((double)CONCAT44(0x43300000,*(uint *)(param_9 + 0x7a) ^ 0x80000000) -
                         DOUBLE_803e3af8);
  *(int *)(param_9 + 0x7a) = (int)(dVar2 - (double)FLOAT_803dc074);
  if (*(int *)(param_9 + 0x7a) < 0) {
    FUN_8002cc9c(dVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  else if (*(char *)(param_9 + 0x1b) != '\0') {
    *(float *)(param_9 + 0x14) = -(FLOAT_803e3aec * FLOAT_803dc074 - *(float *)(param_9 + 0x14));
    *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) * FLOAT_803e3af0;
    *param_9 = *param_9 + 0x38e;
    param_9[2] = param_9[2] + 0x38e;
    param_9[1] = param_9[1] + 0x38e;
    FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
    FUN_80035eec((int)param_9,10,1,0);
    FUN_80035a6c((int)param_9,5);
    FUN_80036018((int)param_9);
    if ((*(int *)(*(int *)(param_9 + 0x2a) + 0x50) == 0) ||
       ((iVar1 = FUN_8002bac4(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) != iVar1 &&
        (iVar1 = FUN_8002ba84(), *(int *)(*(int *)(param_9 + 0x2a) + 0x50) != iVar1)))) {
      if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') {
        FUN_80160098((uint)param_9);
        *(undefined *)(param_9 + 0x1b) = 0;
        param_9[0x7a] = 0;
        param_9[0x7b] = 0x78;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
      }
    }
    else {
      FUN_80160178((uint)param_9);
      *(undefined *)(param_9 + 0x1b) = 0;
      param_9[0x7a] = 0;
      param_9[0x7b] = 0x78;
      *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
    }
  }
  return;
}

