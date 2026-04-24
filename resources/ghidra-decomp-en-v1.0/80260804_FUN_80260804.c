// Function: FUN_80260804
// Entry: 80260804
// Size: 172 bytes

void FUN_80260804(int param_1,int param_2,undefined4 param_3)

{
  *(short *)(param_2 + 4) = *(short *)(param_2 + 4) + 1;
  FUN_80260b14(param_2 + 4,0x1ffc,param_2,param_2 + 2);
  FUN_80241a1c(param_2,0x2000);
  *(undefined4 *)(&DAT_803af2b8 + param_1 * 0x110) = param_3;
  FUN_8025ec14(param_1,*(int *)(&DAT_803af1ec + param_1 * 0x110) *
                       ((uint)(param_2 - (&DAT_803af260)[param_1 * 0x44]) >> 0xd),&LAB_80260588);
  return;
}

