// Function: FUN_8016c958
// Entry: 8016c958
// Size: 676 bytes

/* WARNING: Removing unreachable block (ram,0x8016cbd8) */
/* WARNING: Removing unreachable block (ram,0x8016c968) */

void FUN_8016c958(int param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  double dVar5;
  undefined auStack_38 [8];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  if ((*(uint *)(param_1 + 0xf8) & 4) != 0) {
    dVar5 = (double)FLOAT_803e3ed8;
    for (bVar4 = 0; bVar4 < 10; bVar4 = bVar4 + 1) {
      fVar1 = *(float *)(param_1 + 8);
      uVar2 = (uint)bVar4;
      local_2c = (float)(dVar5 * (double)(fVar1 * (float)(&DAT_803213b8)[uVar2 * 5]));
      local_28 = (float)(dVar5 * (double)(fVar1 * (float)(&DAT_803213bc)[uVar2 * 5]));
      local_24 = (float)(dVar5 * (double)(fVar1 * (float)(&DAT_803213c0)[uVar2 * 5]));
      FUN_8009742c((double)(fVar1 * (float)(&DAT_803213c4)[uVar2 * 5]),param_1,3,
                   (uint)(byte)(&DAT_803213c8)[uVar2 * 0x14],
                   (uint)(byte)(&DAT_803213c9)[uVar2 * 0x14],(int)auStack_38);
    }
  }
  local_30 = FLOAT_803e3edc;
  if ((*(uint *)(param_1 + 0xf8) & 1) != 0) {
    fVar1 = *(float *)(param_1 + 8);
    local_2c = FLOAT_803e3ed8 * FLOAT_803e3ee0 * fVar1;
    local_28 = FLOAT_803e3ed8 * FLOAT_803e3ee4 * fVar1;
    local_24 = FLOAT_803e3ed8 * FLOAT_803e3ee8 * fVar1;
    FUN_80098608((double)(FLOAT_803e3eec * fVar1),(double)FLOAT_803e3ef0);
    local_2c = FLOAT_803e3ef4;
    fVar1 = *(float *)(param_1 + 8);
    local_28 = FLOAT_803e3ed8 * FLOAT_803e3ef8 * fVar1;
    local_24 = FLOAT_803e3ed8 * FLOAT_803e3efc * fVar1;
    FUN_80098608((double)(FLOAT_803e3eec * fVar1),(double)FLOAT_803e3f00);
    fVar1 = *(float *)(param_1 + 8);
    local_2c = FLOAT_803e3ed8 * FLOAT_803e3f04 * fVar1;
    local_28 = FLOAT_803e3ed8 * FLOAT_803e3ee4 * fVar1;
    local_24 = FLOAT_803e3ed8 * FLOAT_803e3ee8 * fVar1;
    FUN_80098608((double)(FLOAT_803e3eec * fVar1),(double)FLOAT_803e3ef0);
  }
  if (*(short *)(param_1 + 0x46) == 0xa8) {
    FUN_80097568((double)FLOAT_803e3f08,(double)FLOAT_803e3f0c,param_1,7,5,1,10,0,0x20000000);
  }
  else if (*(short *)(param_1 + 0x46) == 0x451) {
    iVar3 = FUN_8002b660(param_1);
    *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = 2;
    if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
      FUN_80097568((double)FLOAT_803e3f08,(double)FLOAT_803e3f10,param_1,5,2,1,0x14,0,0);
    }
  }
  return;
}

