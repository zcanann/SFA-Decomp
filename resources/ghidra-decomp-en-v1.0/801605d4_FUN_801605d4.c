// Function: FUN_801605d4
// Entry: 801605d4
// Size: 188 bytes

undefined4 FUN_801605d4(int param_1,int param_2)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2e68,param_1,0,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(undefined *)(param_2 + 0x25f) = 1;
  *(undefined2 *)(param_1 + 4) = *(undefined2 *)(param_2 + 0x19e);
  *(undefined2 *)(param_1 + 2) = *(undefined2 *)(param_2 + 0x19c);
  (**(code **)(*DAT_803dcab8 + 0x10))
            ((double)FLOAT_803e2e8c,(double)FLOAT_803e2e90,param_1,param_2,uVar1);
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2e94 * *(float *)(param_2 + 0x280);
  return 0;
}

