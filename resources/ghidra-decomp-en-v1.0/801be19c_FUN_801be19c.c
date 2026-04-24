// Function: FUN_801be19c
// Entry: 801be19c
// Size: 688 bytes

/* WARNING: Removing unreachable block (ram,0x801be428) */

void FUN_801be19c(int param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined4 uVar1;
  undefined8 in_f31;
  double dVar2;
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar2 = (double)FLOAT_803e4c90;
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 1;
  *(undefined *)(param_4 + 0x25f) = 1;
  (**(code **)(*DAT_803dcab8 + 0x2c))(dVar2,param_1,param_4,1);
  (**(code **)(*DAT_803dcab8 + 0x54))
            (param_1,param_4,param_3 + 0x35c,(int)*(short *)(param_3 + 0x3f4),param_3 + 0x405,0,0,0)
  ;
  if (FLOAT_803e4c90 == FLOAT_803ddba4) {
    dVar2 = (double)(float)(dVar2 + (double)FLOAT_803e4cbc);
  }
  else {
    FLOAT_803ddba4 = FLOAT_803ddba4 - FLOAT_803db414;
    dVar2 = (double)(FLOAT_803ddba4 * FLOAT_803e4cb4);
    if (FLOAT_803ddba4 <= FLOAT_803e4cb8) {
      FLOAT_803ddba4 = FLOAT_803e4c90;
      *(undefined *)(param_4 + 0x349) = 0;
      *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      FUN_800200e8(0x20e,0);
      if (DAT_803ddb94 < '\a') {
        FUN_800200e8(0x268,1);
      }
      else {
        FUN_800200e8(0x311,1);
      }
    }
  }
  if (FLOAT_803ddb9c <= FLOAT_803ddba0) {
    FUN_8000bb18(param_1,0x189);
    if ((double)FLOAT_803e4cbc < dVar2) {
      dVar2 = (double)FLOAT_803e4cbc;
    }
    if (dVar2 < (double)FLOAT_803e4c9c) {
      dVar2 = (double)FLOAT_803e4c9c;
    }
    FLOAT_803ddb9c = (float)((double)FLOAT_803ddb9c + dVar2);
    FUN_80014aa0((double)FLOAT_803e4cc0);
  }
  FLOAT_803ddba0 = FLOAT_803ddba0 + FLOAT_803db414;
  FUN_801bdf7c(param_1,param_4);
  if ((FLOAT_803e4c90 != FLOAT_803ddb98) &&
     (FLOAT_803ddb98 = FLOAT_803ddb98 - FLOAT_803db414, FLOAT_803ddb98 <= FLOAT_803e4c90)) {
    FLOAT_803ddb98 = FLOAT_803e4c90;
    *(undefined *)(param_4 + 0x349) = 0;
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_800200e8(0x20e,0);
    if (DAT_803ddb94 == '\x03') {
      FUN_800200e8(0x268,1);
    }
    else {
      FUN_800200e8(0x311,1);
    }
  }
  *(undefined4 *)(param_3 + 0x3e0) = *(undefined4 *)(param_1 + 0xc0);
  *(undefined4 *)(param_1 + 0xc0) = 0;
  (**(code **)(*DAT_803dca8c + 8))
            ((double)FLOAT_803db414,(double)FLOAT_803db414,param_1,param_4,&DAT_803ddbb0,
             &DAT_803ddba8);
  *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(param_3 + 0x3e0);
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  return;
}

