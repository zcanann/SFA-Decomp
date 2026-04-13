// Function: FUN_801d3160
// Entry: 801d3160
// Size: 228 bytes

void FUN_801d3160(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,int param_11)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0x26);
  iVar1 = FUN_8002ba84();
  if (iVar1 != 0) {
    FUN_80139280(iVar1);
  }
  FUN_8000bb38((uint)param_9,0xa3);
  *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 0x40
  ;
  FUN_8009adfc((double)FLOAT_803e6010,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0,1,1,1,0,1,0);
  *(undefined *)(param_11 + 0x14) = 1;
  *(byte *)(param_11 + 0x15) = *(byte *)(param_11 + 0x15) | 2;
  if ((int)*(short *)(iVar2 + 0x1c) == 0xffffffff) {
    iVar1 = 0;
    do {
      FUN_801d2fd4(param_9);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 3);
  }
  else {
    FUN_800201ac((int)*(short *)(iVar2 + 0x1c),0);
  }
  return;
}

