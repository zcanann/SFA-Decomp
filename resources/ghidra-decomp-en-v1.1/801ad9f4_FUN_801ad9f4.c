// Function: FUN_801ad9f4
// Entry: 801ad9f4
// Size: 236 bytes

undefined4
FUN_801ad9f4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)

{
  int iVar1;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar2;
  double dVar3;
  double dVar4;
  
  if (*(short *)(param_9 + 0x46) != 0x172) {
    pfVar2 = *(float **)(param_9 + 0xb8);
    iVar1 = FUN_8002bac4();
    dVar3 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18));
    dVar4 = (double)*pfVar2;
    if ((dVar4 <= dVar3) || (*(char *)((int)pfVar2 + 0xb) != '\0')) {
      if (((double)(float)((double)FLOAT_803e53d0 + dVar4) < dVar3) &&
         (*(char *)((int)pfVar2 + 0xb) != '\0')) {
        *(undefined *)((int)pfVar2 + 0xb) = 0;
        FUN_800066e0(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                     (uint)*(ushort *)(pfVar2 + 2),0,0,0,in_r9,in_r10);
      }
    }
    else {
      *(undefined *)((int)pfVar2 + 0xb) = 1;
      FUN_800066e0(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   (uint)*(ushort *)((int)pfVar2 + 6),0,0,0,in_r9,in_r10);
    }
  }
  return 0;
}

