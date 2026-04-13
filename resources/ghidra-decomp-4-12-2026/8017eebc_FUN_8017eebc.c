// Function: FUN_8017eebc
// Entry: 8017eebc
// Size: 684 bytes

void FUN_8017eebc(undefined2 *param_1,int param_2)

{
  float fVar1;
  double dVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  
  puVar6 = *(undefined4 **)(param_1 + 0x5c);
  *puVar6 = *(undefined4 *)(param_2 + 0x18);
  dVar2 = DOUBLE_803e44d8;
  puVar6[1] = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x1c)) -
                     DOUBLE_803e44d8);
  puVar6[2] = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x1e)) - dVar2);
  fVar1 = FLOAT_803e44c0;
  puVar6[4] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x20)) - dVar2) /
              FLOAT_803e44c0;
  puVar6[5] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x21)) - dVar2) / fVar1
              + (float)puVar6[4];
  puVar6[6] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x22)) - dVar2) / fVar1
              + (float)puVar6[5];
  puVar6[7] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x23)) - dVar2) / fVar1
              + (float)puVar6[6];
  puVar6[8] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - dVar2) / fVar1;
  puVar6[10] = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x25) ^ 0x80000000) -
                      DOUBLE_803e44b8) / fVar1;
  puVar6[10] = (float)puVar6[10] * FLOAT_803e4474;
  puVar6[9] = FLOAT_803e4460;
  *(undefined2 *)(puVar6 + 0xe) = 0;
  fVar1 = FLOAT_803e446c;
  puVar6[0xf] = FLOAT_803e446c;
  puVar6[0x10] = FLOAT_803e44c4;
  puVar6[0x11] = fVar1;
  fVar1 = (float)puVar6[1] * (float)puVar6[6] * (float)puVar6[1] * (float)puVar6[6];
  fVar1 = fVar1 * fVar1;
  puVar6[0x15] = fVar1 * fVar1 * FLOAT_803e44c8;
  uVar3 = FUN_80022264(0xffff8000,0x7fff);
  *param_1 = (short)uVar3;
  *(float *)(param_1 + 4) = FLOAT_803e44cc;
  FUN_8002b95c((int)param_1,0);
  if (((int)*(short *)(param_2 + 0x26) == 0xffffffff) ||
     (uVar3 = FUN_80020078((int)*(short *)(param_2 + 0x26)), uVar3 == 0)) {
    fVar1 = (float)puVar6[2] / (float)puVar6[1];
    if ((float)puVar6[4] <= fVar1) {
      if ((float)puVar6[5] <= fVar1) {
        if ((float)puVar6[6] <= fVar1) {
          iVar5 = *(int *)(param_1 + 0x5c);
          puVar4 = (undefined4 *)FUN_800395a4((int)param_1,0);
          *puVar4 = 0;
          *(float *)(iVar5 + 0x24) = FLOAT_803e4460;
          *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
          FUN_8002b95c((int)param_1,1);
          *(undefined *)((int)puVar6 + 0x3a) = 3;
        }
        else {
          *(undefined *)((int)puVar6 + 0x3a) = 2;
        }
      }
      else {
        *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
        *(undefined *)((int)puVar6 + 0x3a) = 1;
      }
    }
    else {
      *(undefined *)((int)puVar6 + 0x3a) = 0;
    }
  }
  else {
    puVar6[2] = FLOAT_803e44d0;
    *(undefined *)((int)puVar6 + 0x3a) = 6;
  }
  FUN_80037a5c((int)param_1,2);
  return;
}

