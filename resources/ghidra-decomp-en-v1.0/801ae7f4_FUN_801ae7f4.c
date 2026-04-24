// Function: FUN_801ae7f4
// Entry: 801ae7f4
// Size: 392 bytes

/* WARNING: Removing unreachable block (ram,0x801ae864) */

void FUN_801ae7f4(undefined2 *param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[1] = *(undefined2 *)(param_2 + 0x1a);
  *(char *)((int)param_1 + 0xad) = (char)*(undefined2 *)(param_2 + 0x1c);
  *pbVar4 = *(byte *)(param_2 + 0x19);
  bVar1 = *pbVar4;
  if (bVar1 == 4) {
    *(float *)(param_1 + 4) = FLOAT_803e47b4;
  }
  else if (bVar1 < 4) {
    if (bVar1 < 2) {
      *(float *)(param_1 + 4) = FLOAT_803e47a8;
    }
    else {
      *(float *)(param_1 + 4) = FLOAT_803e47ac;
    }
  }
  else if (bVar1 < 7) {
    *(float *)(param_1 + 4) = FLOAT_803e47b0;
  }
  uVar3 = *(undefined4 *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4);
  FUN_800279cc((double)FLOAT_803e4798,uVar3,0,0xffffffff,0,0);
  FUN_80027980((double)FLOAT_803e4788,uVar3,0);
  bVar1 = *pbVar4;
  if (bVar1 < 5) {
    uVar3 = FUN_80023cc8(0x28,0x12,0);
    *(undefined4 *)(pbVar4 + 4) = uVar3;
    iVar2 = (uint)bVar1 * 2;
    FUN_8001f71c(*(undefined4 *)(pbVar4 + 4),0xc,*(short *)(&DAT_80323818 + iVar2) * 0x28,0x28);
    uVar3 = FUN_80023cc8(0x28,0x12,0);
    *(undefined4 *)(pbVar4 + 8) = uVar3;
    FUN_8001f71c(*(undefined4 *)(pbVar4 + 8),0xc,*(short *)(&DAT_80323824 + iVar2) * 0x28,0x28);
  }
  *(undefined *)(param_1 + 0x1b) = 0;
  return;
}

