// Function: FUN_80211770
// Entry: 80211770
// Size: 308 bytes

void FUN_80211770(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  float fVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  FUN_8002bac4();
  FUN_8000b844(param_9,0x2e9);
  FUN_8000b844(param_9,0x2e8);
  FUN_8000bb38(param_9,0xf1);
  fVar1 = FLOAT_803e7400;
  *(float *)(param_9 + 0x24) = FLOAT_803e7400;
  *(float *)(param_9 + 0x2c) = fVar1;
  FUN_800803f8((undefined4 *)(iVar2 + 0x14));
  FUN_80080404((float *)(iVar2 + 0x14),10);
  *(undefined *)(iVar2 + 0x2c) = 0;
  FUN_80036018(param_9);
  FUN_80035f84(param_9);
  FUN_800803f8((undefined4 *)(iVar2 + 0x1c));
  FUN_8009ab54((double)FLOAT_803e7404,param_9);
  dVar3 = (double)(*(float *)(iVar2 + 8) - FLOAT_803e740c);
  FUN_8009adfc((double)(float)(dVar3 * (double)FLOAT_803dceb4 + (double)FLOAT_803e7408),dVar3,
               param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,0,1,0,1,0);
  FUN_80035c48(param_9,(short)(int)*(float *)(iVar2 + 8),-5,10);
  FUN_80035eec(param_9,0xd,1,0);
  FUN_80036018(param_9);
  if (*(int *)(iVar2 + 4) != 0) {
    FUN_8001cc00((uint *)(iVar2 + 4));
  }
  return;
}

