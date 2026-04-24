// Function: FUN_801b87dc
// Entry: 801b87dc
// Size: 132 bytes

void FUN_801b87dc(int param_1)

{
  float fVar1;
  int iVar2;
  int local_18 [5];
  
  iVar2 = FUN_8003687c(param_1,local_18,0,0);
  if (iVar2 == 0xe) {
    iVar2 = FUN_8002b9ec();
    FUN_80021704(param_1 + 0x18,iVar2 + 0x18);
    fVar1 = FLOAT_803e4adc;
    *(float *)(param_1 + 0x24) = *(float *)(local_18[0] + 0x24) * FLOAT_803e4adc;
    *(float *)(param_1 + 0x2c) = *(float *)(local_18[0] + 0x2c) * fVar1;
    FUN_8000bb18(param_1,0x1f9);
  }
  return;
}

