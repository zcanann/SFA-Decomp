// Function: FUN_80205fb8
// Entry: 80205fb8
// Size: 964 bytes

/* WARNING: Removing unreachable block (ram,0x802060c4) */

void FUN_80205fb8(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int local_28;
  int local_24 [6];
  
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(iVar4 + 4);
  if ((iVar2 == 0) || ((*(ushort *)(iVar2 + 6) & 0x40) == 0)) {
    if (iVar2 == 0) {
      iVar2 = FUN_8002e0fc(local_24,&local_28);
      for (; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
        iVar3 = *(int *)(iVar2 + local_24[0] * 4);
        if (*(short *)(iVar3 + 0x46) == 0x431) {
          *(int *)(iVar4 + 4) = iVar3;
          local_24[0] = local_28;
        }
      }
      if (*(int *)(iVar4 + 4) == 0) {
        return;
      }
    }
    (**(code **)(**(int **)(*(int *)(iVar4 + 4) + 0x68) + 0x20))(*(int *)(iVar4 + 4),&DAT_803299d8);
    iVar2 = FUN_8001ffb4(0x5e4);
    if (iVar2 == 0) {
      *(undefined *)(iVar4 + 9) = 0;
    }
    else {
      *(undefined1 *)(iVar4 + 9) = (&DAT_803299d8)[*(byte *)(iVar4 + 8)];
    }
    bVar1 = *(byte *)(iVar4 + 9);
    if (bVar1 == 2) {
      if (*(char *)(param_1 + 0xad) != '\x02') {
        FUN_8002b884(param_1,2);
      }
      if ((int)*(short *)(iVar5 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e63f8 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e6400) / FLOAT_803e63fc);
      }
      if (*(short *)(param_1 + 4) != 0) {
        *(undefined2 *)(param_1 + 4) = 0;
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        if (*(char *)(param_1 + 0xad) != '\0') {
          FUN_8002b884(param_1,0);
        }
        if ((int)*(short *)(iVar5 + 0x1c) != 0) {
          *(float *)(param_1 + 8) =
               FLOAT_803e63f8 /
               ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1c) ^ 0x80000000) -
                       DOUBLE_803e6400) / FLOAT_803e63fc);
        }
      }
      else {
        if (*(char *)(param_1 + 0xad) != '\x01') {
          FUN_8002b884(param_1,1);
        }
        if ((int)*(short *)(iVar5 + 0x1c) != 0) {
          *(float *)(param_1 + 8) =
               FLOAT_803e63f8 /
               ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1c) ^ 0x80000000) -
                       DOUBLE_803e6400) / FLOAT_803e63fc);
        }
        if (*(short *)(param_1 + 4) != 0) {
          *(undefined2 *)(param_1 + 4) = 0;
        }
      }
    }
    else if (bVar1 == 4) {
      if (*(char *)(param_1 + 0xad) != '\x01') {
        FUN_8002b884(param_1,1);
      }
      if ((int)*(short *)(iVar5 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e63f8 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e6400) / FLOAT_803e63fc);
      }
      if (*(short *)(param_1 + 4) != 0x3fff) {
        *(undefined2 *)(param_1 + 4) = 0x7fff;
      }
    }
    else if (bVar1 < 4) {
      if (*(char *)(param_1 + 0xad) != '\x02') {
        FUN_8002b884(param_1,2);
      }
      if ((int)*(short *)(iVar5 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e63f8 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e6400) / FLOAT_803e63fc);
      }
      if (*(short *)(param_1 + 4) != 0x3fff) {
        *(undefined2 *)(param_1 + 4) = 0x7fff;
      }
    }
    else {
      if (*(char *)(param_1 + 0xad) != '\0') {
        FUN_8002b884(param_1,0);
      }
      if ((int)*(short *)(iVar5 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e63f8 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e6400) / FLOAT_803e63fc);
      }
      if (*(short *)(param_1 + 4) != 0) {
        *(undefined2 *)(param_1 + 4) = 0;
      }
    }
  }
  else {
    *(undefined4 *)(iVar4 + 4) = 0;
  }
  return;
}

