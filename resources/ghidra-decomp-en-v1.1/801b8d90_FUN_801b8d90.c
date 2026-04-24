// Function: FUN_801b8d90
// Entry: 801b8d90
// Size: 132 bytes

void FUN_801b8d90(uint param_1)

{
  float fVar1;
  int iVar2;
  int local_18 [5];
  
  iVar2 = FUN_80036974(param_1,local_18,(int *)0x0,(uint *)0x0);
  if (iVar2 == 0xe) {
    iVar2 = FUN_8002bac4();
    FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
    fVar1 = FLOAT_803e5774;
    *(float *)(param_1 + 0x24) = *(float *)(local_18[0] + 0x24) * FLOAT_803e5774;
    *(float *)(param_1 + 0x2c) = *(float *)(local_18[0] + 0x2c) * fVar1;
    FUN_8000bb38(param_1,0x1f9);
  }
  return;
}

