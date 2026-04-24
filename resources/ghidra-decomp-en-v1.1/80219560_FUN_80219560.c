// Function: FUN_80219560
// Entry: 80219560
// Size: 180 bytes

undefined4 FUN_80219560(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  double dVar3;
  
  iVar1 = FUN_8002bac4();
  iVar2 = *(int *)(param_1 + 0x4c);
  FUN_80035ff8(param_1);
  dVar3 = (double)FUN_80021754((float *)(iVar1 + 0x18),(float *)(param_1 + 0x18));
  if ((double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar2 + 0x1a) ^ 0x80000000) -
                     DOUBLE_803e7618) <= dVar3) {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) & 0xfb;
  }
  else {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
  }
  return 0;
}

