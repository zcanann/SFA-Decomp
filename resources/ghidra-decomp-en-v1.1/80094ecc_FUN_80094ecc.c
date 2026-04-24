// Function: FUN_80094ecc
// Entry: 80094ecc
// Size: 796 bytes

void FUN_80094ecc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 uint param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined2 *puVar3;
  double dVar4;
  double extraout_f1;
  double extraout_f1_00;
  
  puVar2 = FUN_800e877c();
  if (((param_11 != 0) && ((*(byte *)(param_11 + 0x58) & 2) != 0)) &&
     (*(short *)((int)puVar2 + 10) = *(short *)(param_11 + 0x24) + -1,
     (*(byte *)(param_11 + 0x59) & 1) != 0)) {
    DAT_803dc278 = uRam803dc27c;
    uRam803dc27c = param_13 & 0xffff;
    dVar4 = (double)*(float *)(param_11 + 8);
    DAT_8039b7a0 = (undefined)(int)(dVar4 / (double)FLOAT_803dff5c);
    DAT_8039b7a1 = 0;
    DAT_8039b7a2 = (*(byte *)(param_11 + 0x59) & 4) == 0;
    uVar1 = (uint)*(byte *)(param_11 + 0x5d);
    if (uVar1 == 0) {
      if (DAT_8039b788 != 0) {
        dVar4 = (double)FUN_8002cc9c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     DAT_8039b788);
        DAT_8039b788 = 0;
      }
      DAT_8039b794 = 0;
    }
    else if ((uVar1 < 5) && (DAT_8039b794 != *(int *)(&DAT_80310370 + uVar1 * 4))) {
      if (DAT_8039b788 != 0) {
        dVar4 = (double)FUN_8002cc9c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     DAT_8039b788);
      }
      puVar3 = FUN_8002becc(0x20,(short)*(undefined4 *)
                                         (&DAT_80310370 + (uint)*(byte *)(param_11 + 0x5d) * 4));
      DAT_8039b788 = FUN_8002e088(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  puVar3,4,0xff,0xffffffff,(uint *)0x0,param_14,param_15,param_16);
      DAT_8039b794 = *(int *)(&DAT_80310370 + (uint)*(byte *)(param_11 + 0x5d) * 4);
      dVar4 = extraout_f1;
    }
    uVar1 = (uint)*(byte *)(param_11 + 0x5b);
    if (uVar1 == 0) {
      if (DAT_8039b78c != 0) {
        dVar4 = (double)FUN_8002cc9c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     DAT_8039b78c);
        DAT_8039b78c = 0;
      }
      DAT_8039b798 = 0;
    }
    else if ((uVar1 < 4) && (DAT_8039b798 != *(int *)(&DAT_80310384 + uVar1 * 4))) {
      if (DAT_8039b78c != 0) {
        dVar4 = (double)FUN_8002cc9c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     DAT_8039b78c);
      }
      puVar3 = FUN_8002becc(0x20,(short)*(undefined4 *)
                                         (&DAT_80310384 + (uint)*(byte *)(param_11 + 0x5b) * 4));
      DAT_8039b78c = FUN_8002e088(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  puVar3,4,0xff,0xffffffff,(uint *)0x0,param_14,param_15,param_16);
      DAT_8039b798 = *(int *)(&DAT_80310384 + (uint)*(byte *)(param_11 + 0x5b) * 4);
      dVar4 = extraout_f1_00;
    }
    uVar1 = (uint)*(byte *)(param_11 + 0x5a);
    if (uVar1 == 0) {
      if (DAT_8039b790 != 0) {
        FUN_8002cc9c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_8039b790);
        DAT_8039b790 = 0;
      }
      DAT_8039b79c = 0;
    }
    else if ((uVar1 < 5) && (DAT_8039b79c != *(int *)(&DAT_80310394 + uVar1 * 4))) {
      if (DAT_8039b790 != 0) {
        dVar4 = (double)FUN_8002cc9c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     DAT_8039b790);
      }
      puVar3 = FUN_8002becc(0x20,(short)*(undefined4 *)
                                         (&DAT_80310394 + (uint)*(byte *)(param_11 + 0x5a) * 4));
      DAT_8039b790 = FUN_8002e088(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  puVar3,4,0xff,0xffffffff,(uint *)0x0,param_14,param_15,param_16);
      DAT_8039b79c = *(int *)(&DAT_80310394 + (uint)*(byte *)(param_11 + 0x5a) * 4);
    }
  }
  return;
}

