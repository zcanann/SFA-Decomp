// Function: FUN_802065f0
// Entry: 802065f0
// Size: 964 bytes

/* WARNING: Removing unreachable block (ram,0x802066fc) */

void FUN_802065f0(int param_1)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int local_28;
  int local_24 [6];
  
  iVar6 = *(int *)(param_1 + 0x4c);
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(iVar5 + 4);
  if ((iVar2 == 0) || ((*(ushort *)(iVar2 + 6) & 0x40) == 0)) {
    if (iVar2 == 0) {
      iVar2 = FUN_8002e1f4(local_24,&local_28);
      for (; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
        iVar4 = *(int *)(iVar2 + local_24[0] * 4);
        if (*(short *)(iVar4 + 0x46) == 0x431) {
          *(int *)(iVar5 + 4) = iVar4;
          local_24[0] = local_28;
        }
      }
      if (*(int *)(iVar5 + 4) == 0) {
        return;
      }
    }
    (**(code **)(**(int **)(*(int *)(iVar5 + 4) + 0x68) + 0x20))(*(int *)(iVar5 + 4),&DAT_8032a618);
    uVar3 = FUN_80020078(0x5e4);
    if (uVar3 == 0) {
      *(undefined *)(iVar5 + 9) = 0;
    }
    else {
      *(undefined1 *)(iVar5 + 9) = (&DAT_8032a618)[*(byte *)(iVar5 + 8)];
    }
    bVar1 = *(byte *)(iVar5 + 9);
    if (bVar1 == 2) {
      if (*(char *)(param_1 + 0xad) != '\x02') {
        FUN_8002b95c(param_1,2);
      }
      if ((int)*(short *)(iVar6 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e7090 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e7098) / FLOAT_803e7094);
      }
      if (*(short *)(param_1 + 4) != 0) {
        *(undefined2 *)(param_1 + 4) = 0;
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        if (*(char *)(param_1 + 0xad) != '\0') {
          FUN_8002b95c(param_1,0);
        }
        if ((int)*(short *)(iVar6 + 0x1c) != 0) {
          *(float *)(param_1 + 8) =
               FLOAT_803e7090 /
               ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                       DOUBLE_803e7098) / FLOAT_803e7094);
        }
      }
      else {
        if (*(char *)(param_1 + 0xad) != '\x01') {
          FUN_8002b95c(param_1,1);
        }
        if ((int)*(short *)(iVar6 + 0x1c) != 0) {
          *(float *)(param_1 + 8) =
               FLOAT_803e7090 /
               ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                       DOUBLE_803e7098) / FLOAT_803e7094);
        }
        if (*(short *)(param_1 + 4) != 0) {
          *(undefined2 *)(param_1 + 4) = 0;
        }
      }
    }
    else if (bVar1 == 4) {
      if (*(char *)(param_1 + 0xad) != '\x01') {
        FUN_8002b95c(param_1,1);
      }
      if ((int)*(short *)(iVar6 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e7090 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e7098) / FLOAT_803e7094);
      }
      if (*(short *)(param_1 + 4) != 0x3fff) {
        *(undefined2 *)(param_1 + 4) = 0x7fff;
      }
    }
    else if (bVar1 < 4) {
      if (*(char *)(param_1 + 0xad) != '\x02') {
        FUN_8002b95c(param_1,2);
      }
      if ((int)*(short *)(iVar6 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e7090 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e7098) / FLOAT_803e7094);
      }
      if (*(short *)(param_1 + 4) != 0x3fff) {
        *(undefined2 *)(param_1 + 4) = 0x7fff;
      }
    }
    else {
      if (*(char *)(param_1 + 0xad) != '\0') {
        FUN_8002b95c(param_1,0);
      }
      if ((int)*(short *)(iVar6 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e7090 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e7098) / FLOAT_803e7094);
      }
      if (*(short *)(param_1 + 4) != 0) {
        *(undefined2 *)(param_1 + 4) = 0;
      }
    }
  }
  else {
    *(undefined4 *)(iVar5 + 4) = 0;
  }
  return;
}

