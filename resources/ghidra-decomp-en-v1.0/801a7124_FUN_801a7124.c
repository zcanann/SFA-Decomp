// Function: FUN_801a7124
// Entry: 801a7124
// Size: 1660 bytes

void FUN_801a7124(int param_1)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  byte *pbVar5;
  double dVar6;
  double local_38;
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  if ((*pbVar5 & 0x80) == 0) {
    iVar3 = FUN_8001ffb4(0xd52);
    if (iVar3 == 0) {
      bVar4 = FUN_8001ffb4(0x88c);
      pbVar5[2] = bVar4;
    }
    else {
      pbVar5[2] = 1;
    }
    pbVar5[1] = 2;
    FUN_8000da58(param_1,0x107);
    uVar2 = (uint)pbVar5[2] * 0x20 + 0x20;
    if (0x7f < uVar2) {
      uVar2 = 0x7f;
    }
    FUN_8000b888((double)FLOAT_803e44fc,param_1,0x40,uVar2 & 0xff);
    if (pbVar5[2] != 0) {
      fVar1 = *(float *)(param_1 + 0x28);
      if (FLOAT_803e4500 *
          ((*(float *)(pbVar5 + 0xc) + *(float *)(&DAT_803231d0 + (uint)pbVar5[2] * 4)) -
          *(float *)(param_1 + 0x10)) <= fVar1) {
        *(float *)(param_1 + 0x28) = -(FLOAT_803e4508 * FLOAT_803db414 - fVar1);
      }
      else {
        *(float *)(param_1 + 0x28) = FLOAT_803e4504 * FLOAT_803db414 + fVar1;
      }
      dVar6 = DOUBLE_803e4540;
      *(short *)(pbVar5 + 0x14) =
           (short)(int)(FLOAT_803e450c * FLOAT_803db414 +
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(pbVar5 + 0x14)) -
                              DOUBLE_803e4540));
      local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(pbVar5 + 0x16));
      *(short *)(pbVar5 + 0x16) =
           (short)(int)(FLOAT_803e4510 * FLOAT_803db414 + (float)(local_38 - dVar6));
      *(short *)(pbVar5 + 0x18) =
           (short)(int)(FLOAT_803e4514 * FLOAT_803db414 +
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(pbVar5 + 0x18)) - dVar6
                              ));
      FUN_8002b95c((double)FLOAT_803e4518,(double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
                   (double)FLOAT_803e4518,param_1);
      dVar6 = (double)FUN_80293e80((double)((FLOAT_803e451c *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (uint)*(ushort *)
                                                                            (pbVar5 + 0x14)) -
                                                   DOUBLE_803e4540)) / FLOAT_803e4520));
      *(float *)(param_1 + 0x10) = (float)((double)*(float *)(param_1 + 0x10) + dVar6);
      if (*(float *)(param_1 + 0x10) < *(float *)(pbVar5 + 0xc)) {
        *(float *)(param_1 + 0x10) = *(float *)(pbVar5 + 0xc);
      }
      dVar6 = (double)FUN_80293e80((double)((FLOAT_803e451c *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (uint)*(ushort *)
                                                                            (pbVar5 + 0x16)) -
                                                   DOUBLE_803e4540)) / FLOAT_803e4520));
      *(short *)(param_1 + 4) =
           *(short *)(param_1 + 4) + (short)(int)((double)FLOAT_803e4524 * dVar6);
      dVar6 = (double)FUN_80293e80((double)((FLOAT_803e451c *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (uint)*(ushort *)
                                                                            (pbVar5 + 0x18)) -
                                                   DOUBLE_803e4540)) / FLOAT_803e4520));
      *(short *)(param_1 + 2) =
           *(short *)(param_1 + 2) + (short)(int)((double)FLOAT_803e4524 * dVar6);
      DAT_803ac908 = FLOAT_803e44f8;
      DAT_803ac90c = *(undefined4 *)(param_1 + 0xc);
      DAT_803ac910 = *(float *)(pbVar5 + 0xc) - FLOAT_803e4528;
      DAT_803ac914 = *(undefined4 *)(param_1 + 0x14);
      DAT_803ddb30 = (int)(*(float *)(param_1 + 0x10) - *(float *)(pbVar5 + 0xc));
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x722,0,2,0xffffffff,&DAT_803ddb30);
      (**(code **)(*DAT_803dca88 + 8))
                (param_1,0x723,&DAT_803ac900,0x200001,0xffffffff,&DAT_803ddb30);
      (**(code **)(*DAT_803dca88 + 8))
                (param_1,0x723,&DAT_803ac900,0x200001,0xffffffff,&DAT_803ddb30);
    }
  }
  if (*pbVar5 != 0) {
    if ((*pbVar5 & 1) != 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x716,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x716,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x716,0,1,0xffffffff,0);
    }
    if ((*pbVar5 & 8) != 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x71a,0,2,0xffffffff,0);
    }
    if ((*pbVar5 & 0x10) != 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x71b,0,1,0xffffffff,0);
      iVar3 = 0x28;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x71c,0,1,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      FUN_8009ab70((double)FLOAT_803e452c,param_1,1,1,0,1,0,1,0);
      FUN_8000e650((double)FLOAT_803e4530,(double)FLOAT_803e4534,(double)FLOAT_803e4538);
      FUN_80014aa0((double)FLOAT_803e453c);
      *pbVar5 = *pbVar5 & 0xef;
    }
    if ((*pbVar5 & 0x20) != 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x71d,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x71d,0,1,0xffffffff,0);
    }
    if ((*pbVar5 & 0x40) != 0) {
      *(float *)(pbVar5 + 8) = *(float *)(pbVar5 + 8) - FLOAT_803db414;
      if (*(float *)(pbVar5 + 8) < FLOAT_803e4518) {
        uVar2 = FUN_800221a0(10,0x3c);
        *(float *)(pbVar5 + 8) =
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e44f0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x71e,0,1,0xffffffff,0);
      }
    }
  }
  fVar1 = FLOAT_803e4518;
  if ((FLOAT_803e4518 < *(float *)(pbVar5 + 4)) &&
     (*(float *)(pbVar5 + 4) = *(float *)(pbVar5 + 4) - FLOAT_803db414,
     *(float *)(pbVar5 + 4) <= fVar1)) {
    FUN_800200e8(0x88b,0);
  }
  *pbVar5 = *pbVar5 & 0x7f;
  return;
}

