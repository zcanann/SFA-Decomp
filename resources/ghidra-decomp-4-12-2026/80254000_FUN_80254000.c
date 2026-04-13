// Function: FUN_80254000
// Entry: 80254000
// Size: 72 bytes

uint FUN_80254000(int param_1,int param_2,int param_3,int param_4)

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

