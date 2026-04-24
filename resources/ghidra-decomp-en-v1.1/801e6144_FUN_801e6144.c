// Function: FUN_801e6144
// Entry: 801e6144
// Size: 528 bytes

/* WARNING: Removing unreachable block (ram,0x801e6334) */
/* WARNING: Removing unreachable block (ram,0x801e6154) */

void FUN_801e6144(uint param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  bool bVar5;
  double dVar6;
  undefined auStack_38 [6];
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24 [2];
  uint uStack_1c;
  
  iVar4 = FUN_8002bac4();
  dVar6 = (double)FUN_800217c8((float *)(iVar4 + 0x18),(float *)(param_1 + 0x18));
  bVar5 = FUN_8000b598(param_1,0x40);
  if (bVar5) {
    if ((double)FLOAT_803e6618 <= dVar6) {
      FUN_8000b7dc(param_1,0x40);
    }
  }
  else if (dVar6 < (double)FLOAT_803e6618) {
    FUN_8000bb38(param_1,0x72);
  }
  if (*(short *)(param_1 + 0x46) != 0x3e4) {
    if (*(int *)(param_1 + 0xf8) == 0) {
      *(undefined4 *)(param_1 + 0xf8) = 1;
      uStack_1c = FUN_80022264(0,0x5a);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_24[1] = 176.0;
      FUN_800303fc((double)((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6628) /
                           FLOAT_803e6618),param_1);
    }
    FUN_8002fb40((double)FLOAT_803e661c,(double)FLOAT_803dc074);
  }
  if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
    local_30 = FLOAT_803e6614;
    local_32 = 0xc0d;
    local_2c = FLOAT_803e6620;
    local_28 = FLOAT_803e6624;
    local_24[0] = FLOAT_803e6620;
    FUN_80038524(param_1,0,&local_2c,&local_28,local_24,1);
    if (*(int *)(param_1 + 0x30) == 0) {
      fVar1 = *(float *)(param_1 + 0xc);
      fVar2 = *(float *)(param_1 + 0x10);
      fVar3 = *(float *)(param_1 + 0x14);
    }
    else {
      fVar1 = *(float *)(param_1 + 0x18);
      fVar2 = *(float *)(param_1 + 0x1c);
      fVar3 = *(float *)(param_1 + 0x20);
    }
    local_24[0] = local_24[0] - fVar3;
    local_28 = local_28 - fVar2;
    local_2c = local_2c - fVar1;
    for (iVar4 = 0; iVar4 < (int)(uint)DAT_803dc070; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7c7,auStack_38,2,0xffffffff,0);
    }
  }
  return;
}

