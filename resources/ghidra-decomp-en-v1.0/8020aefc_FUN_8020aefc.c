// Function: FUN_8020aefc
// Entry: 8020aefc
// Size: 500 bytes

void FUN_8020aefc(int param_1)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined auStack40 [4];
  undefined auStack36 [4];
  undefined auStack32 [20];
  
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_80036770(param_1,0,0,0,auStack40,auStack36,auStack32);
  if ((iVar2 == 0xf) || (iVar2 == 0xe)) {
    if ((*(byte *)(iVar5 + 0x198) >> 6 & 1) == 0) {
      if (*(float *)(iVar5 + 0x1a0) < FLOAT_803e6510) {
        *(float *)(iVar5 + 0x1a0) = FLOAT_803e6520;
        FUN_8000bb18(param_1,0x4b0);
      }
    }
    else {
      *(int *)(iVar5 + 0x170) = *(int *)(iVar5 + 0x170) + -1;
      *(byte *)(iVar5 + 0x198) = *(byte *)(iVar5 + 0x198) & 0xf7 | 8;
      if (*(int *)(iVar5 + 0x170) < 0) {
        FUN_800200e8((int)*(short *)(iVar4 + 0x1e),1);
        FUN_8009ab70((double)FLOAT_803e6550,param_1,1,1,1,1,1,1,1);
        FUN_8002ce88(param_1);
        (**(code **)(*DAT_803dcaac + 0x44))(0x1d,3);
        FUN_800200e8(0x83c,1);
      }
      else {
        FUN_80221e94((double)FLOAT_803e6554,param_1,auStack40);
      }
      if (*(float *)(iVar5 + 0x19c) <= FLOAT_803e6510) {
        *(float *)(iVar5 + 0x19c) = FLOAT_803e6558;
        FUN_8000bb18(param_1,0x478);
      }
      if (*(float *)(iVar5 + 0x1a0) <= FLOAT_803e6510) {
        *(float *)(iVar5 + 0x1a0) = FLOAT_803e6520;
        FUN_8000bb18(param_1,0x4af);
      }
      fVar1 = FLOAT_803e6518;
      *(float *)(iVar5 + 0x17c) = FLOAT_803e6518;
      *(float *)(iVar5 + 0x178) = fVar1;
      uVar3 = FUN_800221a0(0xffffffce,0x32);
      *(float *)(iVar5 + 0x180) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e6528) /
           FLOAT_803e655c;
    }
  }
  *(float *)(iVar5 + 0x19c) = *(float *)(iVar5 + 0x19c) - FLOAT_803db414;
  *(float *)(iVar5 + 0x1a0) = *(float *)(iVar5 + 0x1a0) - FLOAT_803db414;
  return;
}

