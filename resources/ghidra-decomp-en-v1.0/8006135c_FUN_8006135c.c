// Function: FUN_8006135c
// Entry: 8006135c
// Size: 760 bytes

/* WARNING: Removing unreachable block (ram,0x80061634) */

void FUN_8006135c(undefined2 *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f31;
  float local_a8;
  undefined auStack164 [12];
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = FUN_80065768((double)*(float *)(param_2 + 0xc),(double)*(float *)(param_2 + 0x10),
                       (double)*(float *)(param_2 + 0x14),param_2,&local_a8,auStack164,0);
  if (iVar3 == 0) {
    FUN_80247794(auStack164,auStack164);
    local_8c = FLOAT_803dec68;
    local_88 = FLOAT_803dec58;
    local_84 = FLOAT_803dec58;
    dVar5 = (double)FUN_8024782c(auStack164,&local_8c);
    if ((double)FLOAT_803dec6c <= ABS(dVar5)) {
      local_8c = FLOAT_803dec58;
      local_84 = FLOAT_803dec68;
    }
    FUN_8024784c(auStack164,&local_8c,&local_98);
    FUN_8024784c(&local_98,auStack164,&local_8c);
    FUN_80247794(&local_8c,&local_8c);
    FUN_80247794(&local_98,&local_98);
    dVar5 = (double)(FLOAT_803dec70 * **(float **)(param_2 + 100));
    FUN_80247778(dVar5,&local_8c,&local_8c);
    FUN_80247778(dVar5,&local_98,&local_98);
    fVar2 = FLOAT_803dec74;
    fVar1 = FLOAT_803dec58;
    local_a8 = -local_a8;
    *param_1 = (short)(int)(FLOAT_803dec74 * ((FLOAT_803dec58 - local_8c) - local_98));
    param_1[1] = (short)(int)(fVar2 * ((local_a8 - local_88) - local_94));
    param_1[2] = (short)(int)(fVar2 * ((fVar1 - local_84) - local_90));
    param_1[3] = (short)(int)(fVar2 * ((fVar1 + local_8c) - local_98));
    param_1[4] = (short)(int)(fVar2 * ((local_a8 + local_88) - local_94));
    param_1[5] = (short)(int)(fVar2 * ((fVar1 + local_84) - local_90));
    param_1[6] = (short)(int)(fVar2 * (local_98 + fVar1 + local_8c));
    param_1[7] = (short)(int)(fVar2 * (local_94 + local_a8 + local_88));
    param_1[8] = (short)(int)(fVar2 * (local_90 + fVar1 + local_84));
    param_1[9] = (short)(int)(fVar2 * (local_98 + (fVar1 - local_8c)));
    param_1[10] = (short)(int)(fVar2 * (local_94 + (local_a8 - local_88)));
    param_1[0xb] = (short)(int)(fVar2 * (local_90 + (fVar1 - local_84)));
    *(undefined *)(param_1 + 0xc) = 1;
  }
  else {
    *(undefined *)(param_1 + 0xc) = 0xff;
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

