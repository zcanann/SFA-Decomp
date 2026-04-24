// Function: FUN_8019ae20
// Entry: 8019ae20
// Size: 464 bytes

void FUN_8019ae20(ushort *param_1,short *param_2)

{
  float fVar1;
  short sVar2;
  uint uVar3;
  byte *pbVar4;
  
  FUN_8002b9a0((int)param_1,'(');
  pbVar4 = *(byte **)(param_1 + 0x5c);
  sVar2 = *param_2;
  if (sVar2 == 0x54) {
    *(short *)(pbVar4 + 0x82) = param_2[0x24];
    *(short *)(pbVar4 + 0x84) = param_2[0x25];
    *(short *)(pbVar4 + 0x86) = param_2[0x26];
    *(short *)(pbVar4 + 0x88) = param_2[0x27];
    pbVar4[0x8a] = pbVar4[0x8a] & 0x7f;
  }
  else if (sVar2 < 0x54) {
    if (sVar2 == 0x4d) {
      *param_1 = (ushort)*(byte *)((int)param_2 + 0x3d) << 8;
      param_1[1] = (ushort)*(byte *)(param_2 + 0x1f) << 8;
      param_1[2] = 0;
    }
    else if (sVar2 < 0x4d) {
      if (sVar2 == 0x4b) {
        fVar1 = (float)((double)CONCAT44(0x43300000,
                                         (uint)*(byte *)(param_2 + 0x1d) << 1 ^ 0x80000000) -
                       DOUBLE_803e4d68);
        *(float *)(pbVar4 + 4) = fVar1 * fVar1;
        param_1[2] = 0;
        param_1[1] = 0;
        *param_1 = (ushort)*(byte *)((int)param_2 + 0x3d) << 8;
        *(float *)(param_1 + 4) = fVar1 / FLOAT_803e4d90;
      }
      else if (0x4a < sVar2) {
        *(short *)(pbVar4 + 0x82) = param_2[0x24];
        FUN_80199520(param_1,(int)param_2);
      }
    }
  }
  else if (sVar2 == 0x230) {
    *(float *)(pbVar4 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1d) << 1 ^ 0x80000000) -
                DOUBLE_803e4d68);
    *(float *)(pbVar4 + 4) = *(float *)(pbVar4 + 4) * *(float *)(pbVar4 + 4);
  }
  *(short *)(pbVar4 + 0x80) = param_2[0x22];
  uVar3 = FUN_80020078((int)*(short *)(pbVar4 + 0x80));
  if (uVar3 == 1) {
    *pbVar4 = *pbVar4 | 4;
  }
  *pbVar4 = *pbVar4 | 0x40;
  return;
}

