// Function: FUN_801a76d8
// Entry: 801a76d8
// Size: 1660 bytes

void FUN_801a76d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  double dVar5;
  undefined8 local_38;
  
  pbVar4 = *(byte **)(param_9 + 0xb8);
  if ((*pbVar4 & 0x80) == 0) {
    uVar2 = FUN_80020078(0xd52);
    if (uVar2 == 0) {
      uVar2 = FUN_80020078(0x88c);
      pbVar4[2] = (byte)uVar2;
    }
    else {
      pbVar4[2] = 1;
    }
    pbVar4[1] = 2;
    FUN_8000da78(param_9,0x107);
    uVar2 = (uint)pbVar4[2] * 0x20 + 0x20;
    if (0x7f < uVar2) {
      uVar2 = 0x7f;
    }
    FUN_8000b8a8((double)FLOAT_803e5194,param_9,0x40,(byte)uVar2);
    if (pbVar4[2] != 0) {
      fVar1 = *(float *)(param_9 + 0x28);
      if (FLOAT_803e5198 *
          ((*(float *)(pbVar4 + 0xc) + *(float *)((uint)pbVar4[2] * 4 + -0x7fcdc1f0)) -
          *(float *)(param_9 + 0x10)) <= fVar1) {
        *(float *)(param_9 + 0x28) = -(FLOAT_803e51a0 * FLOAT_803dc074 - fVar1);
      }
      else {
        *(float *)(param_9 + 0x28) = FLOAT_803e519c * FLOAT_803dc074 + fVar1;
      }
      dVar5 = DOUBLE_803e51d8;
      *(short *)(pbVar4 + 0x14) =
           (short)(int)(FLOAT_803e51a4 * FLOAT_803dc074 +
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(pbVar4 + 0x14)) -
                              DOUBLE_803e51d8));
      local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(pbVar4 + 0x16));
      *(short *)(pbVar4 + 0x16) =
           (short)(int)(FLOAT_803e51a8 * FLOAT_803dc074 + (float)(local_38 - dVar5));
      *(short *)(pbVar4 + 0x18) =
           (short)(int)(FLOAT_803e51ac * FLOAT_803dc074 +
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(pbVar4 + 0x18)) - dVar5
                              ));
      param_3 = (double)FLOAT_803e51b0;
      FUN_8002ba34(param_3,(double)(*(float *)(param_9 + 0x28) * FLOAT_803dc074),param_3,param_9);
      dVar5 = (double)FUN_802945e0();
      *(float *)(param_9 + 0x10) = (float)((double)*(float *)(param_9 + 0x10) + dVar5);
      if (*(float *)(param_9 + 0x10) < *(float *)(pbVar4 + 0xc)) {
        *(float *)(param_9 + 0x10) = *(float *)(pbVar4 + 0xc);
      }
      dVar5 = (double)FUN_802945e0();
      *(short *)(param_9 + 4) =
           *(short *)(param_9 + 4) + (short)(int)((double)FLOAT_803e51bc * dVar5);
      param_2 = (double)FLOAT_803e51b4;
      dVar5 = (double)FUN_802945e0();
      *(short *)(param_9 + 2) =
           *(short *)(param_9 + 2) + (short)(int)((double)FLOAT_803e51bc * dVar5);
      DAT_803ad568 = FLOAT_803e5190;
      DAT_803ad56c = *(undefined4 *)(param_9 + 0xc);
      DAT_803ad570 = *(float *)(pbVar4 + 0xc) - FLOAT_803e51c0;
      DAT_803ad574 = *(undefined4 *)(param_9 + 0x14);
      DAT_803de7b0 = (int)(*(float *)(param_9 + 0x10) - *(float *)(pbVar4 + 0xc));
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x722,0,2,0xffffffff,&DAT_803de7b0);
      (**(code **)(*DAT_803dd708 + 8))
                (param_9,0x723,&DAT_803ad560,0x200001,0xffffffff,&DAT_803de7b0);
      (**(code **)(*DAT_803dd708 + 8))
                (param_9,0x723,&DAT_803ad560,0x200001,0xffffffff,&DAT_803de7b0);
    }
  }
  if (*pbVar4 != 0) {
    if ((*pbVar4 & 1) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x716,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x716,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x716,0,1,0xffffffff,0);
    }
    if ((*pbVar4 & 8) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x71a,0,2,0xffffffff,0);
    }
    if ((*pbVar4 & 0x10) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x71b,0,1,0xffffffff,0);
      iVar3 = 0x28;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_9,0x71c,0,1,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      FUN_8009adfc((double)FLOAT_803e51c4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,1,0,1,0,1,0);
      FUN_8000e670((double)FLOAT_803e51c8,(double)FLOAT_803e51cc,(double)FLOAT_803e51d0);
      FUN_80014acc((double)FLOAT_803e51d4);
      *pbVar4 = *pbVar4 & 0xef;
    }
    if ((*pbVar4 & 0x20) != 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x71d,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x71d,0,1,0xffffffff,0);
    }
    if (((*pbVar4 & 0x40) != 0) &&
       (*(float *)(pbVar4 + 8) = *(float *)(pbVar4 + 8) - FLOAT_803dc074,
       *(float *)(pbVar4 + 8) < FLOAT_803e51b0)) {
      uVar2 = FUN_80022264(10,0x3c);
      *(float *)(pbVar4 + 8) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5188);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x71e,0,1,0xffffffff,0);
    }
  }
  fVar1 = FLOAT_803e51b0;
  if (FLOAT_803e51b0 < *(float *)(pbVar4 + 4)) {
    *(float *)(pbVar4 + 4) = *(float *)(pbVar4 + 4) - FLOAT_803dc074;
    if (*(float *)(pbVar4 + 4) <= fVar1) {
      FUN_800201ac(0x88b,0);
    }
  }
  *pbVar4 = *pbVar4 & 0x7f;
  return;
}

