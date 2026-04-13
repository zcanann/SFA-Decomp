// Function: FUN_801a2014
// Entry: 801a2014
// Size: 744 bytes

void FUN_801a2014(int *param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  double dVar7;
  float local_80;
  undefined4 local_7c;
  undefined4 local_78;
  float local_74;
  float local_70;
  float local_6c;
  int aiStack_68 [7];
  float local_4c;
  undefined4 local_48;
  undefined4 local_44;
  char local_17;
  
  iVar6 = param_1[0x2e];
  iVar4 = FUN_80037ad4(*(int *)(iVar6 + 0x10));
  if ((iVar4 == 0) && (*(int *)(iVar6 + 0x10) != 0)) {
    FUN_80037da8((int)param_1,*(int *)(iVar6 + 0x10));
    *(undefined4 *)(iVar6 + 0x10) = 0;
  }
  if (((*(char *)(iVar6 + 0x17) == '\0') &&
      (uVar5 = FUN_800803dc((float *)(iVar6 + 0x18)), uVar5 == 0)) &&
     (uVar5 = FUN_800803dc((float *)(iVar6 + 0x1c)), uVar5 == 0)) {
    if (*(short **)(iVar6 + 0xc) != (short *)0x0) {
      FUN_80063000((short *)param_1,*(short **)(iVar6 + 0xc),1);
      *(undefined4 *)(iVar6 + 0xc) = 0;
    }
    if (*(char *)(iVar6 + 0x4a) < '\0') {
      fVar1 = (float)param_1[4];
      fVar2 = (float)param_1[0x21];
      fVar3 = FLOAT_803e4fbc * FLOAT_803dc078;
      local_74 = ((float)param_1[3] - (float)param_1[0x20]) * fVar3;
      local_6c = ((float)param_1[5] - (float)param_1[0x22]) * fVar3;
      *(float *)(iVar6 + 0x20) = local_74 + *(float *)(iVar6 + 0x20);
      *(float *)(iVar6 + 0x24) = (fVar1 - fVar2) * fVar3 + *(float *)(iVar6 + 0x24);
      *(float *)(iVar6 + 0x28) = local_6c + *(float *)(iVar6 + 0x28);
      fVar2 = FLOAT_803e4fc0;
      fVar1 = FLOAT_803e4f58;
      local_70 = FLOAT_803e4f58;
      *(float *)(iVar6 + 0x20) = FLOAT_803e4fc0 * *(float *)(iVar6 + 0x20);
      *(float *)(iVar6 + 0x24) = fVar2 * *(float *)(iVar6 + 0x24);
      *(float *)(iVar6 + 0x28) = fVar2 * *(float *)(iVar6 + 0x28);
      *(float *)(iVar6 + 0x24) = fVar1;
      *(byte *)(iVar6 + 0x49) = *(byte *)(iVar6 + 0x49) | 1;
    }
    if ((*(char *)(iVar6 + 0x15) == '\0') &&
       (iVar4 = FUN_80064248(param_1 + 0x20,param_1 + 3,(float *)0x1,aiStack_68,param_1,8,0xffffffff
                             ,0xff,0), iVar4 != 0)) {
      if (local_17 == '\x14') {
        *(undefined *)(iVar6 + 0x16) = 4;
      }
      if ((*(char *)(iVar6 + 0x4a) < '\0') && (local_17 == '\x03')) {
        FUN_801a1380((int)param_1,'\0');
        FUN_8003709c((int)param_1,0x16);
      }
      else {
        local_80 = local_4c;
        local_7c = local_48;
        local_78 = local_44;
        FUN_80022800(&local_80,(float *)(param_1 + 9),(float *)(param_1 + 9));
        FUN_80022800(&local_80,(float *)(iVar6 + 0x20),(float *)(iVar6 + 0x20));
        fVar1 = FLOAT_803e4fc8;
        param_1[9] = (int)(FLOAT_803e4fc8 * (float)param_1[9]);
        param_1[10] = (int)(fVar1 * (float)param_1[10]);
        param_1[0xb] = (int)(fVar1 * (float)param_1[0xb]);
        *(float *)(iVar6 + 0x20) = fVar1 * *(float *)(iVar6 + 0x20);
        *(float *)(iVar6 + 0x24) = fVar1 * *(float *)(iVar6 + 0x24);
        *(float *)(iVar6 + 0x28) = fVar1 * *(float *)(iVar6 + 0x28);
        if (FLOAT_803e4fcc < *(float *)(iVar6 + 0x54)) {
          dVar7 = FUN_80247f54((float *)(iVar6 + 0x20));
          if ((double)FLOAT_803dcaec < dVar7) {
            FUN_8000bb38((uint)param_1,0x446);
          }
          *(float *)(iVar6 + 0x54) = FLOAT_803e4f58;
        }
      }
    }
    param_1[0x20] = param_1[3];
    param_1[0x21] = param_1[4];
    param_1[0x22] = param_1[5];
  }
  return;
}

