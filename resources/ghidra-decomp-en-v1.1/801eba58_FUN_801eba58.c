// Function: FUN_801eba58
// Entry: 801eba58
// Size: 532 bytes

/* WARNING: Removing unreachable block (ram,0x801ebc44) */
/* WARNING: Removing unreachable block (ram,0x801ebc3c) */
/* WARNING: Removing unreachable block (ram,0x801ebc34) */
/* WARNING: Removing unreachable block (ram,0x801eba78) */
/* WARNING: Removing unreachable block (ram,0x801eba70) */
/* WARNING: Removing unreachable block (ram,0x801eba68) */

undefined4 FUN_801eba58(short *param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  short local_a8 [4];
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float afStack_90 [16];
  longlong local_50;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  *(code **)(param_3 + 0xe8) = FUN_801eb96c;
  FUN_80035ff8((int)param_1);
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    bVar2 = *(byte *)(param_3 + iVar3 + 0x81);
    if (bVar2 == 3) {
      (**(code **)(*DAT_803dd6e8 + 0x60))();
    }
    else if ((((bVar2 < 3) && (1 < bVar2)) && (param_1[0x23] != 0x16c)) && (param_1[0x23] != 0x16f))
    {
      FUN_800201ac(0x499,1);
    }
  }
  if (*(char *)(iVar4 + 0x421) == '\x02') {
    dVar7 = (double)(FLOAT_803dc078 * (*(float *)(param_1 + 6) - *(float *)(iVar4 + 0x16c)));
    dVar6 = (double)(FLOAT_803dc078 * (*(float *)(param_1 + 8) - *(float *)(iVar4 + 0x170)));
    dVar5 = (double)(FLOAT_803dc078 * (*(float *)(param_1 + 10) - *(float *)(iVar4 + 0x174)));
    local_9c = FLOAT_803e6780;
    local_98 = FLOAT_803e6780;
    local_94 = FLOAT_803e6780;
    local_a0 = FLOAT_803e6784;
    local_a8[0] = -*param_1;
    local_a8[1] = 0;
    local_a8[2] = 0;
    FUN_80021c64(afStack_90,(int)local_a8);
    FUN_80022790(dVar7,dVar6,dVar5,afStack_90,(float *)(iVar4 + 0x494),(float *)(iVar4 + 0x498),
                 (float *)(iVar4 + 0x49c));
    *(char *)(iVar4 + 0x460) = *(char *)(iVar4 + 0x460) + DAT_803dc070 * '\b';
    if ('F' < *(char *)(iVar4 + 0x460)) {
      *(undefined *)(iVar4 + 0x460) = 0x46;
    }
    uVar1 = (uint)(FLOAT_803e6838 * -*(float *)(iVar4 + 0x430));
    local_50 = (longlong)(int)uVar1;
    FUN_801ea878((double)*(float *)(iVar4 + 0x49c),(uint)param_1,iVar4,uVar1,iVar4 + 0x461,4);
  }
  *(byte *)(iVar4 + 0x428) = *(byte *)(iVar4 + 0x428) & 0xf7;
  return 0;
}

