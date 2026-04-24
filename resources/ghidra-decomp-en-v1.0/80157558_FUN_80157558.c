// Function: FUN_80157558
// Entry: 80157558
// Size: 832 bytes

void FUN_80157558(short *param_1,int param_2)

{
  float fVar1;
  short sVar2;
  bool bVar3;
  uint uVar4;
  uint uVar5;
  
  *(float *)(param_2 + 0x324) = *(float *)(param_2 + 0x324) - FLOAT_803db414;
  if (*(float *)(param_2 + 0x324) <= FLOAT_803e2b18) {
    uVar5 = FUN_800221a0(0x3c,0x78);
    *(float *)(param_2 + 0x324) =
         (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e2b20);
  }
  if (FLOAT_803e2b18 == *(float *)(param_2 + 0x328)) {
    bVar3 = false;
  }
  else {
    FUN_80035f00(param_1);
    if (param_1[0x50] == 5) {
      if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
        FUN_80035f20(param_1);
        *(float *)(param_2 + 0x328) = FLOAT_803e2b18;
      }
    }
    else {
      FUN_8014d08c((double)FLOAT_803dbcec,param_1,param_2,5,0,0);
    }
    *(undefined *)(param_1 + 0x1b) = 0xff;
    bVar3 = true;
  }
  if (!bVar3) {
    *param_1 = (short)(int)((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x338))
                                   - DOUBLE_803e2b58) * FLOAT_803db414 +
                           (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                  DOUBLE_803e2b20));
    fVar1 = FLOAT_803e2b18;
    *(float *)(param_1 + 0x12) = FLOAT_803e2b18;
    *(float *)(param_1 + 0x14) = fVar1;
    *(float *)(param_1 + 0x16) = fVar1;
    FUN_80035df4(param_1,9,1,0xffffffff);
    uVar5 = FUN_800217c0((double)(*(float *)(param_1 + 6) -
                                 *(float *)(*(int *)(param_2 + 0x29c) + 0xc)),
                         (double)(*(float *)(param_1 + 10) -
                                 *(float *)(*(int *)(param_2 + 0x29c) + 0x14)));
    fVar1 = (float)((double)CONCAT44(0x43300000,
                                     (uVar5 & 0xffff) - ((int)*param_1 & 0xffffU) ^ 0x80000000) -
                   DOUBLE_803e2b20);
    if (FLOAT_803e2b2c < fVar1) {
      fVar1 = FLOAT_803e2b28 + fVar1;
    }
    if (fVar1 < FLOAT_803e2b34) {
      fVar1 = FLOAT_803e2b30 + fVar1;
    }
    uVar5 = (uint)(short)(int)fVar1;
    if ((int)uVar5 < 0) {
      uVar5 = -uVar5;
    }
    FUN_80035f20(param_1);
    uVar4 = *(uint *)(param_2 + 0x2dc) & 0x40000000;
    if ((uVar4 == 0) || (param_1[0x50] != 6)) {
      if ((uVar4 != 0) ||
         (((((uVar5 & 0xffff) < 1000 && (sVar2 = param_1[0x50], sVar2 != 2)) && (sVar2 != 4)) &&
          (sVar2 != 6)))) {
        if ((uVar5 & 0xffff) < 1000) {
          if (FLOAT_803e2b60 <= *(float *)(param_2 + 0x2ac)) {
            FUN_8014d08c((double)FLOAT_803dbce4,param_1,param_2,6,0,0);
          }
          else {
            FUN_8014d08c((double)FLOAT_803e2b44,param_1,param_2,2,0,0);
          }
          *(undefined2 *)(param_2 + 0x338) = 0;
        }
        else {
          FUN_8014d08c((double)FLOAT_803e2b44,param_1,param_2,1,0,0);
          if ((short)(int)fVar1 < 0) {
            *(undefined2 *)(param_2 + 0x338) = 0xfed4;
          }
          else {
            *(undefined2 *)(param_2 + 0x338) = 300;
          }
        }
      }
      param_1[1] = *(short *)(param_2 + 0x19c);
      param_1[2] = *(short *)(param_2 + 0x19e);
    }
    else {
      FUN_8014d08c((double)FLOAT_803dbce0,param_1,param_2,4,0,1);
    }
  }
  return;
}

