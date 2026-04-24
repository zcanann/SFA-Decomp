// Function: FUN_8017e964
// Entry: 8017e964
// Size: 684 bytes

void FUN_8017e964(undefined2 *param_1,int param_2)

{
  float fVar1;
  double dVar2;
  undefined2 uVar5;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar6;
  
  puVar6 = *(undefined4 **)(param_1 + 0x5c);
  *puVar6 = *(undefined4 *)(param_2 + 0x18);
  dVar2 = DOUBLE_803e3840;
  puVar6[1] = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x1c)) -
                     DOUBLE_803e3840);
  puVar6[2] = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x1e)) - dVar2);
  fVar1 = FLOAT_803e3828;
  puVar6[4] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x20)) - dVar2) /
              FLOAT_803e3828;
  puVar6[5] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x21)) - dVar2) / fVar1
              + (float)puVar6[4];
  puVar6[6] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x22)) - dVar2) / fVar1
              + (float)puVar6[5];
  puVar6[7] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x23)) - dVar2) / fVar1
              + (float)puVar6[6];
  puVar6[8] = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x24)) - dVar2) / fVar1;
  puVar6[10] = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x25) ^ 0x80000000) -
                      DOUBLE_803e3820) / fVar1;
  puVar6[10] = (float)puVar6[10] * FLOAT_803e37dc;
  puVar6[9] = FLOAT_803e37c8;
  *(undefined2 *)(puVar6 + 0xe) = 0;
  fVar1 = FLOAT_803e37d4;
  puVar6[0xf] = FLOAT_803e37d4;
  puVar6[0x10] = FLOAT_803e382c;
  puVar6[0x11] = fVar1;
  fVar1 = (float)puVar6[1] * (float)puVar6[6] * (float)puVar6[1] * (float)puVar6[6];
  fVar1 = fVar1 * fVar1;
  puVar6[0x15] = fVar1 * fVar1 * FLOAT_803e3830;
  uVar5 = FUN_800221a0(0xffff8000,0x7fff);
  *param_1 = uVar5;
  *(float *)(param_1 + 4) = FLOAT_803e3834;
  FUN_8002b884(param_1,0);
  if ((*(short *)(param_2 + 0x26) == -1) || (iVar3 = FUN_8001ffb4(), iVar3 == 0)) {
    fVar1 = (float)puVar6[2] / (float)puVar6[1];
    if ((float)puVar6[4] <= fVar1) {
      if ((float)puVar6[5] <= fVar1) {
        if ((float)puVar6[6] <= fVar1) {
          iVar3 = *(int *)(param_1 + 0x5c);
          puVar4 = (undefined4 *)FUN_800394ac(param_1,0,0);
          *puVar4 = 0;
          *(float *)(iVar3 + 0x24) = FLOAT_803e37c8;
          *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
          FUN_8002b884(param_1,1);
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
    puVar6[2] = FLOAT_803e3838;
    *(undefined *)((int)puVar6 + 0x3a) = 6;
  }
  FUN_80037964(param_1,2);
  return;
}

