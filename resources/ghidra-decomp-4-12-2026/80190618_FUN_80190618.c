// Function: FUN_80190618
// Entry: 80190618
// Size: 580 bytes

void FUN_80190618(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  float fVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar5;
  double dVar6;
  
  pfVar5 = *(float **)(param_9 + 0x5c);
  iVar1 = FUN_8002bac4();
  *param_9 = *param_9 + *(short *)(pfVar5 + 0x47);
  param_9[2] = param_9[2] + *(short *)(pfVar5 + 0x46);
  param_9[1] = param_9[1] + *(short *)((int)pfVar5 + 0x11a);
  if ((*(byte *)(pfVar5 + 0x48) & 1) == 0) {
    *(float *)(param_9 + 6) = *(float *)(param_9 + 0x12) * FLOAT_803dc074 + *(float *)(param_9 + 6);
    *(float *)(param_9 + 8) = *(float *)(param_9 + 0x14) * FLOAT_803dc074 + *(float *)(param_9 + 8);
    param_2 = (double)*(float *)(param_9 + 0x16);
    dVar6 = (double)FLOAT_803dc074;
    *(float *)(param_9 + 10) = (float)(param_2 * dVar6 + (double)*(float *)(param_9 + 10));
    if (((*(byte *)(pfVar5 + 0x48) & 2) != 0) &&
       (param_2 = (double)*(float *)(param_9 + 0x14), (double)FLOAT_803e4b10 < param_2)) {
      dVar6 = (double)FLOAT_803e4b14;
      *(float *)(param_9 + 0x14) = (float)(dVar6 * (double)FLOAT_803dc074 + param_2);
    }
  }
  else {
    dVar6 = (double)pfVar5[0x43];
    iVar2 = FUN_80010340(dVar6,pfVar5);
    if ((iVar2 != 0) || (pfVar5[4] != 0.0)) {
      dVar6 = (double)(**(code **)(*DAT_803dd71c + 0x90))(pfVar5);
    }
    *(float *)(param_9 + 6) = pfVar5[0x1a];
    *(float *)(param_9 + 8) = pfVar5[0x1b];
    *(float *)(param_9 + 10) = pfVar5[0x1c];
  }
  if ((iVar1 != 0) &&
     (((int)*(short *)((int)pfVar5 + 0x116) == 0xffffffff ||
      (uVar3 = FUN_80020078((int)*(short *)((int)pfVar5 + 0x116)), uVar3 != 0)))) {
    if ((*(char *)((int)pfVar5 + 0x11e) == '\0') ||
       (*(ushort *)(pfVar5 + 0x44) = *(short *)(pfVar5 + 0x44) - (ushort)DAT_803dc070,
       0 < *(short *)(pfVar5 + 0x44))) {
      if (*(char *)((int)pfVar5 + 0x11f) == '\0') {
        if ((pfVar5 == (float *)0x0) || ((int)*(short *)((int)pfVar5 + 0x112) != DAT_803ad41e - 1))
        {
          fVar4 = (float)FUN_80023d8c(0x28,0x12);
          pfVar5[0x42] = fVar4;
          FUN_8001f7e0(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,pfVar5[0x42],
                       0xc,*(short *)((int)pfVar5 + 0x112) * 0x28,0x28,in_r7,in_r8,in_r9,in_r10);
          if ((undefined2 *)pfVar5[0x42] != (undefined2 *)0x0) {
            FUN_801904c4((undefined2 *)pfVar5[0x42],(undefined2 *)&DAT_803ad410);
          }
        }
        else {
          fVar4 = (float)FUN_80023d8c(0x28,0x12);
          pfVar5[0x42] = fVar4;
          if ((undefined2 *)pfVar5[0x42] != (undefined2 *)0x0) {
            FUN_801904c4((undefined2 *)&DAT_803ad410,(undefined2 *)pfVar5[0x42]);
          }
        }
        *(undefined *)((int)pfVar5 + 0x11f) = 1;
      }
    }
    else {
      FUN_8002cc9c(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  return;
}

