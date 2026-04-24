// Function: FUN_800e5f40
// Entry: 800e5f40
// Size: 380 bytes

void FUN_800e5f40(short *param_1,int param_2)

{
  float fVar1;
  short sVar2;
  int iVar3;
  float local_78;
  float local_74;
  float local_70;
  short local_6c [4];
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float afStack_54 [20];
  
  if ((*(byte *)(param_2 + 0x260) & 0x10) == 0) {
    *(short *)(param_2 + 0x198) =
         *(short *)(param_2 + 0x198) -
         (short)((int)((int)*(short *)(param_2 + 0x198) * (uint)DAT_803dc070) >> 3);
    *(short *)(param_2 + 0x19a) =
         *(short *)(param_2 + 0x19a) -
         (short)((int)((int)*(short *)(param_2 + 0x19a) * (uint)DAT_803dc070) >> 3);
    fVar1 = FLOAT_803e12e8;
    *(float *)(param_2 + 0x1a0) = FLOAT_803e12e8;
    *(float *)(param_2 + 0x1a4) = FLOAT_803e130c;
    *(float *)(param_2 + 0x1a8) = fVar1;
  }
  else {
    local_6c[0] = -*param_1;
    if (*(short **)(param_1 + 0x18) != (short *)0x0) {
      local_6c[0] = local_6c[0] - **(short **)(param_1 + 0x18);
    }
    local_6c[1] = 0;
    local_6c[2] = 0;
    local_64 = FLOAT_803e130c;
    local_60 = FLOAT_803e12e8;
    local_5c = FLOAT_803e12e8;
    local_58 = FLOAT_803e12e8;
    FUN_80021c64(afStack_54,(int)local_6c);
    FUN_80022790((double)*(float *)(param_2 + 0x1a0),(double)*(float *)(param_2 + 0x1a4),
                 (double)*(float *)(param_2 + 0x1a8),afStack_54,&local_70,&local_74,&local_78);
    iVar3 = FUN_80021884();
    sVar2 = 0x4000 - (short)iVar3;
    *(short *)(param_2 + 0x19c) = sVar2;
    *(short *)(param_2 + 0x198) =
         *(short *)(param_2 + 0x198) +
         (short)((int)((uint)DAT_803dc070 * ((int)sVar2 - (int)*(short *)(param_2 + 0x198))) >> 3);
    iVar3 = FUN_80021884();
    sVar2 = -(0x4000 - (short)iVar3);
    *(short *)(param_2 + 0x19e) = sVar2;
    *(short *)(param_2 + 0x19a) =
         *(short *)(param_2 + 0x19a) +
         (short)((int)((uint)DAT_803dc070 * ((int)sVar2 - (int)*(short *)(param_2 + 0x19a))) >> 3);
  }
  return;
}

