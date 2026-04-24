// Function: FUN_8016ae70
// Entry: 8016ae70
// Size: 332 bytes

void FUN_8016ae70(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 auStack_18 [4];
  
  iVar3 = *(int *)(param_9 + 0xb8);
  uVar1 = FUN_800803dc((float *)(iVar3 + 0x20));
  if (uVar1 == 0) {
    iVar2 = FUN_80036974(param_9,auStack_18,(int *)0x0,(uint *)0x0);
    if ((iVar2 == 0xe) || (iVar2 == 0xf)) {
      if (*(short *)(*(int *)(iVar3 + 0x1c) + 4) != -1) {
        FUN_8009adfc((double)FLOAT_803e3df4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,1,0,1,0,1,0);
        FUN_8000b4f0(param_9,*(ushort *)(*(int *)(iVar3 + 0x1c) + 4),3);
      }
      FUN_80035ff8(param_9);
      FUN_80080404((float *)(iVar3 + 0x20),0x78);
    }
    if (*(char *)(*(int *)(param_9 + 0x54) + 0xad) != '\0') {
      FUN_80035ff8(param_9);
      *(float *)(iVar3 + 8) = FLOAT_803e3df8;
      if (*(short *)(*(int *)(iVar3 + 0x1c) + 4) != -1) {
        FUN_8009adfc((double)FLOAT_803e3df4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,1,0,1,0,1,0);
        FUN_8000b4f0(param_9,*(ushort *)(*(int *)(iVar3 + 0x1c) + 4),3);
      }
      FUN_80080404((float *)(iVar3 + 0x20),0x78);
    }
  }
  return;
}

