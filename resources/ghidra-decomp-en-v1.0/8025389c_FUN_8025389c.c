// Function: FUN_8025389c
// Entry: 8025389c
// Size: 72 bytes

uint FUN_8025389c(int param_1,int param_2,int param_3,int param_4)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = (&DAT_cc006800)[param_1 * 5];
  uVar2 = uVar1 & 0x7f5;
  if (param_2 != 0) {
    uVar2 = uVar2 | 2;
  }
  if (param_3 != 0) {
    uVar2 = uVar2 | 8;
  }
  if (param_4 != 0) {
    uVar2 = uVar2 | 0x800;
  }
  (&DAT_cc006800)[param_1 * 5] = uVar2;
  return uVar1;
}

