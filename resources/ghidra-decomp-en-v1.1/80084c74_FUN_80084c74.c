// Function: FUN_80084c74
// Entry: 80084c74
// Size: 624 bytes

/* WARNING: Removing unreachable block (ram,0x80084ec0) */
/* WARNING: Removing unreachable block (ram,0x80084eb8) */
/* WARNING: Removing unreachable block (ram,0x80084eb0) */
/* WARNING: Removing unreachable block (ram,0x80084c94) */
/* WARNING: Removing unreachable block (ram,0x80084c8c) */
/* WARNING: Removing unreachable block (ram,0x80084c84) */

void FUN_80084c74(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  if (iVar2 != 0) {
    if (*(int *)(param_2 + 0x28) < 0) {
      dVar5 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar2 + 8));
      dVar6 = (double)(*(float *)(param_1 + 0x14) - *(float *)(iVar2 + 0x10));
      uStack_4c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
      local_50 = 0x43300000;
      dVar3 = (double)FUN_802945e0();
      uStack_44 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
      local_48 = 0x43300000;
      dVar4 = (double)FUN_80294964();
      *(float *)(param_1 + 0xc) =
           (float)(dVar3 * dVar6 + (double)(float)(dVar4 * dVar5 + (double)*(float *)(iVar2 + 8)));
      *(float *)(param_1 + 0x14) =
           -(float)(dVar3 * dVar5 -
                   (double)(float)(dVar4 * dVar6 + (double)*(float *)(iVar2 + 0x10)));
    }
    else {
      iVar1 = (**(code **)(*DAT_803dd71c + 0x1c))();
      if (iVar1 != 0) {
        local_5c = *(float *)(param_1 + 0xc);
        local_68 = local_5c - *(float *)(iVar2 + 8);
        dVar4 = (double)local_68;
        local_58 = *(float *)(param_1 + 0x10);
        local_64 = local_58 - *(float *)(iVar2 + 0xc);
        local_54 = *(float *)(param_1 + 0x14);
        local_60 = local_54 - *(float *)(iVar2 + 0x10);
        dVar3 = (double)local_60;
        if (*(int *)(iVar1 + 0x1c) < 0) {
          *(float *)(param_1 + 0xc) = local_5c;
          *(float *)(param_1 + 0x10) = local_58;
          *(float *)(param_1 + 0x14) = local_54;
        }
        else {
          iVar1 = FUN_80084744(*(undefined4 *)(param_2 + 0x2c),&local_68,&local_5c,
                               (short *)(param_2 + 0x1a),*(char *)(param_2 + 0x7a));
          if (iVar1 == 0) {
            uStack_44 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
            local_48 = 0x43300000;
            dVar5 = (double)FUN_802945e0();
            uStack_4c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
            local_50 = 0x43300000;
            dVar6 = (double)FUN_80294964();
            *(float *)(param_1 + 0xc) =
                 (float)(dVar5 * dVar3 +
                        (double)(float)(dVar6 * dVar4 + (double)*(float *)(iVar2 + 8)));
            *(float *)(param_1 + 0x14) =
                 -(float)(dVar5 * dVar4 -
                         (double)(float)(dVar6 * dVar3 + (double)*(float *)(iVar2 + 0x10)));
          }
          else {
            *(float *)(param_1 + 0xc) = local_5c;
            *(float *)(param_1 + 0x10) = local_58;
            *(float *)(param_1 + 0x14) = local_54;
          }
        }
      }
    }
  }
  return;
}

