// Function: FUN_801c0af0
// Entry: 801c0af0
// Size: 1136 bytes

/* WARNING: Removing unreachable block (ram,0x801c0f38) */
/* WARNING: Removing unreachable block (ram,0x801c0b00) */

void FUN_801c0af0(uint param_1)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  byte *pbVar5;
  double dVar6;
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((int)*(short *)(iVar4 + 0x20) == 0xffffffff) {
    *(float *)(pbVar5 + 0xc) = *(float *)(pbVar5 + 0xc) - FLOAT_803dc074;
    if (*(float *)(pbVar5 + 0xc) <= FLOAT_803e5a38) {
      uVar1 = FUN_80022264(0xf0,0x1e0);
      *(float *)(pbVar5 + 0xc) =
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5a60);
      *pbVar5 = *pbVar5 | 1;
      *(undefined4 *)(pbVar5 + 4) = *(undefined4 *)(&DAT_803269a8 + (uint)pbVar5[1] * 4);
      *(undefined4 *)(pbVar5 + 8) = *(undefined4 *)(pbVar5 + 4);
      pbVar5[1] = pbVar5[1] + 1;
      if (9 < pbVar5[1]) {
        pbVar5[1] = 0;
      }
    }
  }
  else {
    uVar1 = FUN_80020078((int)*(short *)(iVar4 + 0x20));
    if (uVar1 != 0) {
      FUN_800201ac((int)*(short *)(iVar4 + 0x20),0);
      *pbVar5 = *pbVar5 | 1;
      *(undefined4 *)(pbVar5 + 4) = *(undefined4 *)(&DAT_803269a8 + (uint)pbVar5[1] * 4);
      *(undefined4 *)(pbVar5 + 8) = *(undefined4 *)(pbVar5 + 4);
      pbVar5[1] = pbVar5[1] + 1;
      if (9 < pbVar5[1]) {
        pbVar5[1] = 0;
      }
    }
  }
  if (FLOAT_803e5a38 < *(float *)(pbVar5 + 4)) {
    if ((*pbVar5 & 1) != 0) {
      *pbVar5 = *pbVar5 & 0xfe;
      FUN_80035eec(param_1,9,1,0);
      FUN_80035a6c(param_1,0xf);
      FUN_80036018(param_1);
      if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
        iVar3 = 0;
        do {
          if (*(short *)(iVar4 + 0x1a) == 0) {
            (**(code **)(*DAT_803dd708 + 8))(param_1,0x4cc,0,2,0xffffffff,0);
          }
          else {
            (**(code **)(*DAT_803dd708 + 8))(param_1,0x4c9,0,2,0xffffffff,0);
          }
          iVar3 = iVar3 + 1;
        } while (iVar3 < 0x32);
      }
      iVar3 = FUN_8002bac4();
      if ((iVar3 != 0) && ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0)) {
        dVar6 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
        if (dVar6 <= (double)FLOAT_803e5a3c) {
          dVar6 = (double)(FLOAT_803e5a40 - (float)(dVar6 / (double)FLOAT_803e5a3c));
          FUN_8000e670((double)(float)((double)FLOAT_803e5a44 * dVar6),(double)FLOAT_803e5a44,
                       (double)FLOAT_803e5a48);
          FUN_80014acc((double)(float)((double)FLOAT_803e5a4c * dVar6));
        }
      }
      if (*(int *)(pbVar5 + 0x10) == 0) {
        piVar2 = FUN_8001f58c(param_1,'\x01');
        *(int **)(pbVar5 + 0x10) = piVar2;
        if (*(int *)(pbVar5 + 0x10) != 0) {
          FUN_8001dbf0(*(int *)(pbVar5 + 0x10),2);
          FUN_8001dbd8(*(int *)(pbVar5 + 0x10),1);
          if (*(short *)(iVar4 + 0x1a) == 0) {
            FUN_8001dbb4(*(int *)(pbVar5 + 0x10),0x7f,0xff,0,0);
          }
          else {
            FUN_8001dbb4(*(int *)(pbVar5 + 0x10),0xff,0x7f,0,0);
          }
          FUN_8001dcfc((double)FLOAT_803e5a50,(double)FLOAT_803e5a54,*(int *)(pbVar5 + 0x10));
          FUN_8001dc30((double)FLOAT_803e5a38,*(int *)(pbVar5 + 0x10),'\x01');
          FUN_8001dc30((double)(*(float *)(pbVar5 + 4) / FLOAT_803e5a58),*(int *)(pbVar5 + 0x10),
                       '\0');
        }
      }
      FUN_8000bb38(param_1,0x188);
    }
    *(float *)(pbVar5 + 4) = *(float *)(pbVar5 + 4) - FLOAT_803dc074;
    if (FLOAT_803e5a38 < *(float *)(pbVar5 + 4)) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x4ca,0,2,0xffffffff,0);
      if (*(short *)(iVar4 + 0x1a) == 0) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x4cd,0,2,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x4cb,0,2,0xffffffff,0);
      }
    }
    else {
      *(float *)(pbVar5 + 4) = FLOAT_803e5a38;
      if (*(uint *)(pbVar5 + 0x10) != 0) {
        FUN_8001f448(*(uint *)(pbVar5 + 0x10));
        pbVar5[0x10] = 0;
        pbVar5[0x11] = 0;
        pbVar5[0x12] = 0;
        pbVar5[0x13] = 0;
      }
      FUN_80035eec(param_1,0,0,0);
      FUN_80035a6c(param_1,0);
      FUN_80035ff8(param_1);
    }
  }
  return;
}

