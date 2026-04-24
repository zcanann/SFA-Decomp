// Function: FUN_801aeda8
// Entry: 801aeda8
// Size: 392 bytes

/* WARNING: Removing unreachable block (ram,0x801aee18) */

void FUN_801aeda8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar5;
  byte *pbVar6;
  undefined8 uVar7;
  
  pbVar6 = *(byte **)(param_9 + 0x5c);
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  param_9[1] = *(undefined2 *)(param_10 + 0x1a);
  *(char *)((int)param_9 + 0xad) = (char)*(undefined2 *)(param_10 + 0x1c);
  *pbVar6 = *(byte *)(param_10 + 0x19);
  bVar1 = *pbVar6;
  if (bVar1 == 4) {
    *(float *)(param_9 + 4) = FLOAT_803e544c;
  }
  else if (bVar1 < 4) {
    if (bVar1 < 2) {
      *(float *)(param_9 + 4) = FLOAT_803e5440;
    }
    else {
      *(float *)(param_9 + 4) = FLOAT_803e5444;
    }
  }
  else if (bVar1 < 7) {
    *(float *)(param_9 + 4) = FLOAT_803e5448;
  }
  piVar5 = *(int **)(*(int *)(param_9 + 0x3e) + *(char *)((int)param_9 + 0xad) * 4);
  uVar4 = 0;
  FUN_80027a90((double)FLOAT_803e5430,piVar5,0,-1,0,0);
  uVar7 = FUN_80027a44((double)FLOAT_803e5420,piVar5,0);
  bVar1 = *pbVar6;
  if (bVar1 < 5) {
    iVar2 = FUN_80023d8c(0x28,0x12);
    *(int *)(pbVar6 + 4) = iVar2;
    iVar2 = (uint)bVar1 * 2;
    uVar7 = FUN_8001f7e0(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         *(undefined4 *)(pbVar6 + 4),0xc,*(short *)(&DAT_80324458 + iVar2) * 0x28,
                         0x28,uVar4,in_r8,in_r9,in_r10);
    iVar3 = FUN_80023d8c(0x28,0x12);
    *(int *)(pbVar6 + 8) = iVar3;
    FUN_8001f7e0(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(undefined4 *)(pbVar6 + 8),0xc,*(short *)(&DAT_80324464 + iVar2) * 0x28,0x28,uVar4
                 ,in_r8,in_r9,in_r10);
  }
  *(undefined *)(param_9 + 0x1b) = 0;
  return;
}

