// Function: FUN_8014ed54
// Entry: 8014ed54
// Size: 1168 bytes

void FUN_8014ed54(ushort *param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  double dVar6;
  uint uStack_58;
  int iStack_54;
  undefined4 uStack_50;
  float local_4c;
  float local_48;
  float local_44;
  undefined auStack_40 [12];
  float local_34;
  undefined4 uStack_30;
  float local_2c;
  undefined8 local_28;
  undefined8 local_20;
  
  piVar5 = *(int **)(param_1 + 0x5c);
  iVar4 = *piVar5;
  iVar3 = *(int *)(param_1 + 0x26);
  if (*(int *)(param_1 + 0x7a) == 0) {
    iVar2 = FUN_8002bac4();
    dVar6 = (double)FUN_800217c8((float *)(param_1 + 0xc),(float *)(iVar2 + 0x18));
    if ((double)FLOAT_803e32f0 <= dVar6) {
      if ((double)FLOAT_803e32f4 < dVar6) {
        FUN_8000b844((int)param_1,0x236);
      }
    }
    else {
      FUN_8000bb38((uint)param_1,0x236);
    }
    if ((*(byte *)(param_1 + 0x1b) == 0) || ((*(byte *)((int)piVar5 + 0x26) & 0x18) == 0)) {
      iVar2 = FUN_80036868((int)param_1,&uStack_50,&iStack_54,&uStack_58,&local_34,&uStack_30,
                           &local_2c);
      if (iVar2 != 0) {
        FUN_8000b7dc((int)param_1,0x7f);
        *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 0x10;
        FUN_8000bb38((uint)param_1,0x232);
        FUN_8000bb38((uint)param_1,0x233);
        FUN_8000bb38((uint)param_1,0x238);
        FUN_8000bb38((uint)param_1,0x1f2);
        local_34 = local_34 + FLOAT_803dda58;
        local_2c = local_2c + FLOAT_803dda5c;
        FUN_8009a468(param_1,auStack_40,3,(int *)0x0);
        local_20 = (double)CONCAT44(0x43300000,*(short *)(iVar3 + 0x1c) * 0x3c ^ 0x80000000);
        (**(code **)(*DAT_803dd72c + 100))
                  ((double)(float)(local_20 - DOUBLE_803e32e0),*(undefined4 *)(iVar3 + 0x14));
        if ((int)*(short *)(iVar3 + 0x20) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar3 + 0x20),1);
        }
      }
      FUN_80035eec((int)param_1,10,1,0);
      FUN_80036018((int)param_1);
    }
    else {
      if ((*(byte *)((int)piVar5 + 0x26) & 0x10) != 0) {
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b));
        iVar2 = (int)((float)(local_28 - DOUBLE_803e32d8) - FLOAT_803dc074);
        local_20 = (double)(longlong)iVar2;
        *(char *)(param_1 + 0x1b) = (char)iVar2;
        if (*(byte *)(param_1 + 0x1b) < 7) {
          param_1[0x7a] = 0;
          param_1[0x7b] = 1;
          *(undefined *)(param_1 + 0x1b) = 0;
          *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xef;
          FUN_8000b844((int)param_1,0x236);
        }
        FUN_80035ff8((int)param_1);
      }
      if ((*(byte *)((int)piVar5 + 0x26) & 8) != 0) {
        local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b));
        iVar2 = (int)((float)(local_20 - DOUBLE_803e32d8) + FLOAT_803dc074);
        local_28 = (double)(longlong)iVar2;
        *(char *)(param_1 + 0x1b) = (char)iVar2;
        if (0xf8 < *(byte *)(param_1 + 0x1b)) {
          *(undefined *)(param_1 + 0x1b) = 0xff;
          *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xf7;
        }
      }
    }
    iVar2 = FUN_8002bac4();
    piVar5[1] = iVar2;
    iVar2 = piVar5[1];
    if (iVar2 != 0) {
      local_4c = *(float *)(iVar2 + 0x18) - *(float *)(param_1 + 0xc);
      local_48 = *(float *)(iVar2 + 0x1c) - *(float *)(param_1 + 0xe);
      local_44 = *(float *)(iVar2 + 0x20) - *(float *)(param_1 + 0x10);
      dVar6 = FUN_80293900((double)(local_44 * local_44 + local_4c * local_4c + local_48 * local_48)
                          );
      piVar5[4] = (int)(float)dVar6;
    }
    if (iVar4 != 0) {
      local_4c = *(float *)(iVar4 + 0x68) - *(float *)(param_1 + 0xc);
      local_48 = *(float *)(iVar4 + 0x6c) - *(float *)(param_1 + 0xe);
      local_44 = *(float *)(iVar4 + 0x70) - *(float *)(param_1 + 0x10);
      dVar6 = FUN_80293900((double)(local_44 * local_44 + local_4c * local_4c + local_48 * local_48)
                          );
      piVar5[5] = (int)(float)dVar6;
    }
    if (((*(byte *)((int)piVar5 + 0x26) & 2) != 0) && (FLOAT_803e32fc < (float)piVar5[5])) {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xfd;
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 4;
    }
    if (((*(byte *)((int)piVar5 + 0x26) & 4) != 0) && ((float)piVar5[5] < FLOAT_803e3300)) {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xfb;
    }
    if (((((*(byte *)((int)piVar5 + 0x26) & 6) == 0) && (*(short *)(iVar3 + 0x1e) == 0)) &&
        (piVar5[1] != 0)) && ((float)piVar5[4] < (float)piVar5[6])) {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 2;
    }
    FUN_8014e670(param_1,piVar5);
  }
  else if ((((int)*(short *)(iVar3 + 0x20) == 0xffffffff) ||
           (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20)), uVar1 == 0)) &&
          (iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar3 + 0x14)), iVar3 != 0))
  {
    param_1[0x7a] = 0;
    param_1[0x7b] = 0;
    *(undefined *)(param_1 + 0x1b) = 1;
    *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 8;
    FUN_8000bb38((uint)param_1,0x237);
  }
  return;
}

