// Function: FUN_80160690
// Entry: 80160690
// Size: 96 bytes

undefined4 FUN_80160690(int param_1,int param_2)

{
  float fVar1;
  
  fVar1 = FLOAT_803e2e68;
  *(float *)(param_2 + 0x280) = FLOAT_803e2e68;
  *(float *)(param_2 + 0x284) = fVar1;
  *(float *)(param_2 + 0x2a0) = fVar1;
  *(undefined *)(param_2 + 0x25f) = 1;
  *(undefined2 *)(param_1 + 4) = *(undefined2 *)(param_2 + 0x19e);
  *(undefined2 *)(param_1 + 2) = *(undefined2 *)(param_2 + 0x19c);
  (**(code **)(*DAT_803dca8c + 0x30))(param_1,param_2,5);
  return 0;
}

