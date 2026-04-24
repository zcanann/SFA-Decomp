// Function: FUN_802110f8
// Entry: 802110f8
// Size: 308 bytes

void FUN_802110f8(int param_1)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8002b9ec();
  FUN_8000b824(param_1,0x2e9);
  FUN_8000b824(param_1,0x2e8);
  FUN_8000bb18(param_1,0xf1);
  fVar1 = FLOAT_803e6768;
  *(float *)(param_1 + 0x24) = FLOAT_803e6768;
  *(float *)(param_1 + 0x2c) = fVar1;
  FUN_8008016c(iVar2 + 0x14);
  FUN_80080178(iVar2 + 0x14,10);
  *(undefined *)(iVar2 + 0x2c) = 0;
  FUN_80035f20(param_1);
  FUN_80035e8c(param_1);
  FUN_8008016c(iVar2 + 0x1c);
  FUN_8009a8c8((double)FLOAT_803e676c,param_1);
  FUN_8009ab70((double)((*(float *)(iVar2 + 8) - FLOAT_803e6774) * FLOAT_803dc24c + FLOAT_803e6770),
               param_1,1,1,0,1,0,1,0);
  FUN_80035b50(param_1,(int)*(float *)(iVar2 + 8),0xfffffffb,10);
  FUN_80035df4(param_1,0xd,1,0);
  FUN_80035f20(param_1);
  if (*(int *)(iVar2 + 4) != 0) {
    FUN_8001cb3c(iVar2 + 4);
  }
  return;
}

