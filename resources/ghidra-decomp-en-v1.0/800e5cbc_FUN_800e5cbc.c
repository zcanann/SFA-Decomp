// Function: FUN_800e5cbc
// Entry: 800e5cbc
// Size: 380 bytes

void FUN_800e5cbc(short *param_1,int param_2)

{
  float fVar1;
  short sVar2;
  float local_78;
  float local_74;
  float local_70;
  short local_6c;
  undefined2 local_6a;
  undefined2 local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  undefined auStack84 [80];
  
  if ((*(byte *)(param_2 + 0x260) & 0x10) == 0) {
    *(short *)(param_2 + 0x198) =
         *(short *)(param_2 + 0x198) -
         (short)((int)((int)*(short *)(param_2 + 0x198) * (uint)DAT_803db410) >> 3);
    *(short *)(param_2 + 0x19a) =
         *(short *)(param_2 + 0x19a) -
         (short)((int)((int)*(short *)(param_2 + 0x19a) * (uint)DAT_803db410) >> 3);
    fVar1 = FLOAT_803e0668;
    *(float *)(param_2 + 0x1a0) = FLOAT_803e0668;
    *(float *)(param_2 + 0x1a4) = FLOAT_803e068c;
    *(float *)(param_2 + 0x1a8) = fVar1;
  }
  else {
    local_6c = -*param_1;
    if (*(short **)(param_1 + 0x18) != (short *)0x0) {
      local_6c = local_6c - **(short **)(param_1 + 0x18);
    }
    local_6a = 0;
    local_68 = 0;
    local_64 = FLOAT_803e068c;
    local_60 = FLOAT_803e0668;
    local_5c = FLOAT_803e0668;
    local_58 = FLOAT_803e0668;
    FUN_80021ba0(auStack84,&local_6c);
    FUN_800226cc((double)*(float *)(param_2 + 0x1a0),(double)*(float *)(param_2 + 0x1a4),
                 (double)*(float *)(param_2 + 0x1a8),auStack84,&local_70,&local_74,&local_78);
    sVar2 = FUN_800217c0((double)local_74,(double)local_78);
    *(short *)(param_2 + 0x19c) = 0x4000 - sVar2;
    *(short *)(param_2 + 0x198) =
         *(short *)(param_2 + 0x198) +
         (short)((int)((uint)DAT_803db410 *
                      ((int)(short)(0x4000 - sVar2) - (int)*(short *)(param_2 + 0x198))) >> 3);
    sVar2 = FUN_800217c0((double)local_74,(double)local_70);
    *(short *)(param_2 + 0x19e) = -(0x4000 - sVar2);
    *(short *)(param_2 + 0x19a) =
         *(short *)(param_2 + 0x19a) +
         (short)((int)((uint)DAT_803db410 *
                      ((int)(short)-(0x4000 - sVar2) - (int)*(short *)(param_2 + 0x19a))) >> 3);
  }
  return;
}

