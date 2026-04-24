// Function: FUN_801b466c
// Entry: 801b466c
// Size: 528 bytes

/* WARNING: Removing unreachable block (ram,0x801b4854) */
/* WARNING: Removing unreachable block (ram,0x801b484c) */
/* WARNING: Removing unreachable block (ram,0x801b4684) */
/* WARNING: Removing unreachable block (ram,0x801b467c) */
/* WARNING: Removing unreachable block (ram,0x801b47dc) */

void FUN_801b466c(byte param_1,undefined *param_2)

{
  undefined uVar1;
  undefined uVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  double dVar6;
  
  dVar6 = (double)FUN_80292538();
  sVar3 = 0xff - ((ushort)(int)(FLOAT_803de7e4 * (float)((double)FLOAT_803e55d0 * dVar6)) & 0xff);
  dVar6 = (double)FUN_80292538();
  sVar4 = 0xff - ((ushort)(int)(FLOAT_803de7e0 * (float)((double)FLOAT_803e55d0 * dVar6)) & 0xff);
  dVar6 = (double)FUN_80292538();
  sVar5 = 0xff - ((ushort)(int)(FLOAT_803de7dc * (float)((double)FLOAT_803e55d0 * dVar6)) & 0xff);
  if (sVar3 < 1) {
    sVar3 = 1;
  }
  else if (0xff < sVar3) {
    sVar3 = 0xff;
  }
  if (sVar4 < 1) {
    sVar4 = 1;
  }
  else if (0xff < sVar4) {
    sVar4 = 0xff;
  }
  if (sVar5 < 1) {
    sVar5 = 1;
  }
  else if (0xff < sVar5) {
    sVar5 = 0xff;
  }
  uVar2 = (undefined)sVar3;
  uVar1 = (undefined)sVar5;
  if (param_1 == 2) {
    *param_2 = uVar1;
    param_2[1] = uVar2;
    param_2[2] = uVar1;
  }
  else if (param_1 < 2) {
    if (param_1 == 0) {
      *param_2 = uVar2;
      param_2[1] = (char)sVar4;
      param_2[2] = uVar1;
    }
    else {
      *param_2 = uVar2;
      param_2[1] = uVar1;
      param_2[2] = uVar1;
    }
  }
  else if (param_1 < 4) {
    *param_2 = uVar1;
    param_2[1] = uVar1;
    param_2[2] = uVar2;
  }
  return;
}

