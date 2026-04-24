// Function: FUN_801550d0
// Entry: 801550d0
// Size: 232 bytes

void FUN_801550d0(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e3680;
  *(undefined4 *)(param_2 + 0x2e4) = 0x8000009;
  *(float *)(param_2 + 0x308) = FLOAT_803e3668;
  *(float *)(param_2 + 0x300) = FLOAT_803e364c;
  *(float *)(param_2 + 0x304) = FLOAT_803e3684;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e3688;
  *(float *)(param_2 + 0x314) = FLOAT_803e3688;
  *(undefined *)(param_2 + 0x321) = 1;
  *(float *)(param_2 + 0x318) = FLOAT_803e362c;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  fVar1 = FLOAT_803e3628;
  *(float *)(param_2 + 0x324) = FLOAT_803e3628;
  *(float *)(param_2 + 0x328) = fVar1;
  *(undefined4 *)(param_2 + 0x32c) = *(undefined4 *)(param_1 + 0x10);
  uVar2 = FUN_80022264(0,0xff);
  *(char *)(param_2 + 0x33a) = (char)uVar2;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(float *)(param_2 + 0x330) = FLOAT_803e368c;
  uVar2 = FUN_80022264(0x32,0x4b);
  *(float *)(param_2 + 0x2fc) =
       FLOAT_803e3690 * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3640);
  return;
}

