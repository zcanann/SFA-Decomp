// Function: FUN_80218ee8
// Entry: 80218ee8
// Size: 180 bytes

undefined4 FUN_80218ee8(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  double dVar3;
  
  iVar1 = FUN_8002b9ec();
  iVar2 = *(int *)(param_1 + 0x4c);
  FUN_80035f00(param_1);
  dVar3 = (double)FUN_80021690(iVar1 + 0x18,param_1 + 0x18);
  if ((double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar2 + 0x1a) ^ 0x80000000) -
                     DOUBLE_803e6980) <= dVar3) {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) & 0xfb;
  }
  else {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
  }
  return 0;
}

