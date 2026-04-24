// Function: FUN_802229a8
// Entry: 802229a8
// Size: 504 bytes

/* WARNING: Removing unreachable block (ram,0x80222b78) */
/* WARNING: Removing unreachable block (ram,0x80222b70) */
/* WARNING: Removing unreachable block (ram,0x80222b68) */
/* WARNING: Removing unreachable block (ram,0x802229c8) */
/* WARNING: Removing unreachable block (ram,0x802229c0) */
/* WARNING: Removing unreachable block (ram,0x802229b8) */

int FUN_802229a8(double param_1,double param_2,double param_3,int param_4,float *param_5,
                char param_6)

{
  int iVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  float local_58;
  float local_54;
  float local_50;
  undefined4 local_48;
  uint uStack_44;
  
  iVar4 = 0;
  local_58 = *(float *)(param_4 + 0xc) - param_5[0x1a];
  local_50 = *(float *)(param_4 + 0x14) - param_5[0x1c];
  dVar5 = FUN_80293900((double)(local_58 * local_58 + local_50 * local_50));
  if (dVar5 < param_2) {
    iVar1 = FUN_80010340(param_1,param_5);
    if ((iVar1 != 0) || (param_5[4] != 0.0)) {
      cVar2 = (**(code **)(*DAT_803dd71c + 0x90))(param_5);
      if (cVar2 == '\0') {
        iVar4 = (int)*(char *)((int)param_5[0x27] + 0x18);
      }
      else {
        iVar4 = -1;
      }
    }
    param_3 = (double)(float)((double)FLOAT_803e7910 * param_1);
  }
  local_58 = param_5[0x1a] - *(float *)(param_4 + 0xc);
  local_54 = param_5[0x1b] - *(float *)(param_4 + 0x10);
  local_50 = param_5[0x1c] - *(float *)(param_4 + 0x14);
  if (param_6 == '\0') {
    iVar3 = *(int *)(param_4 + 0xb8);
    local_58 = *(float *)(param_4 + 0xc) - param_5[0x1a];
    local_50 = *(float *)(param_4 + 0x14) - param_5[0x1c];
    iVar1 = FUN_80021884();
    uStack_44 = -(int)(short)iVar1 ^ 0x80000000;
    local_48 = 0x43300000;
    dVar5 = (double)FUN_802945e0();
    *(float *)(iVar3 + 0x290) = (float)(param_3 * -dVar5);
    dVar5 = (double)FUN_80294964();
    *(float *)(iVar3 + 0x28c) = (float)(param_3 * -dVar5);
  }
  else {
    FUN_80222564(param_3,(double)(float)(param_3 / (double)FLOAT_803e7914),(double)FLOAT_803e7918,
                 param_4,(float *)(param_4 + 0x24),&local_58);
  }
  return iVar4;
}

