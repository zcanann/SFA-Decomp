// Function: FUN_801bcd98
// Entry: 801bcd98
// Size: 848 bytes

void FUN_801bcd98(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar3 = FUN_80286840();
  iVar5 = *(int *)(param_11 + 0x40c);
  iVar4 = FUN_8002ba84();
  FUN_80036018(iVar3);
  *(undefined *)(param_12 + 0x25f) = 1;
  (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e5908,iVar3,param_12,1);
  (**(code **)(*DAT_803dd738 + 0x54))
            (iVar3,param_12,param_11 + 0x35c,(int)*(short *)(param_11 + 0x3f4),param_11 + 0x405,0,0,
             0);
  if (*(short *)(param_12 + 0x274) == 6) {
    param_3 = (double)FLOAT_803dc074;
    param_2 = (double)FLOAT_803e5860;
    *(float *)(iVar5 + 0xa0) =
         -(float)(param_3 * (double)(float)(param_2 * (double)*(float *)(iVar3 + 0x98) +
                                           (double)FLOAT_803e58dc) -
                 (double)*(float *)(iVar5 + 0xa0));
  }
  else {
    *(float *)(iVar5 + 0xa0) = *(float *)(iVar5 + 0xa0) - FLOAT_803dc074;
  }
  dVar6 = (double)*(float *)(iVar5 + 0xa0);
  if (dVar6 <= (double)FLOAT_803e5870) {
    dVar6 = (double)FUN_800201ac((uint)*(ushort *)
                                        (&DAT_80326624 + (uint)*(byte *)(iVar5 + 0xb5) * 8),1);
    *(undefined4 *)(iVar5 + 0xa0) =
         *(undefined4 *)(&DAT_80326620 + (uint)*(byte *)(iVar5 + 0xb5) * 8);
    *(char *)(iVar5 + 0xb5) = *(char *)(iVar5 + 0xb5) + '\x01';
    if (0x17 < *(byte *)(iVar5 + 0xb5)) {
      *(undefined *)(iVar5 + 0xb5) = 0;
    }
  }
  fVar2 = FLOAT_803e590c;
  if (iVar4 != 0) {
    fVar1 = *(float *)(iVar5 + 0xa4);
    if ((FLOAT_803e5870 < fVar1) && (fVar1 <= FLOAT_803e590c)) {
      *(float *)(iVar5 + 0xa4) = fVar1 + FLOAT_803dc074;
      if (fVar2 <= *(float *)(iVar5 + 0xa4)) {
        (**(code **)(**(int **)(iVar4 + 0x68) + 0x34))(iVar4,1,iVar3);
      }
    }
    fVar2 = FLOAT_803e5870;
    dVar6 = (double)*(float *)(iVar5 + 0xa8);
    param_2 = (double)FLOAT_803e5870;
    if (dVar6 <= param_2) {
      if (*(short *)(param_11 + 0x402) == 1) {
        *(ushort *)(param_11 + 0x400) = *(ushort *)(param_11 + 0x400) | 4;
        *(float *)(iVar5 + 0xa8) = FLOAT_803e58dc;
        dVar6 = (double)FUN_801bb99c(iVar3,'\0');
      }
    }
    else {
      *(float *)(iVar5 + 0xa8) = (float)(dVar6 + (double)FLOAT_803dc074);
      dVar6 = (double)*(float *)(iVar5 + 0xa8);
      if ((double)FLOAT_803e5884 <= dVar6) {
        *(ushort *)(param_11 + 0x400) = *(ushort *)(param_11 + 0x400) & 0xfffb;
        *(float *)(iVar5 + 0xa8) = fVar2;
        dVar6 = (double)(**(code **)(**(int **)(iVar4 + 0x68) + 0x34))(iVar4,0,0);
        *(float *)(iVar5 + 0xa4) = FLOAT_803e58dc;
      }
    }
  }
  if (*(short *)(param_11 + 0x402) == 2) {
    dVar6 = (double)FUN_801bb99c(iVar3,'\x01');
  }
  if ((DAT_803de800 & 0x20000) != 0) {
    DAT_803de800 = DAT_803de800 & 0xfffdffff;
    FUN_801bb8dc(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_11 + 0x40c) + 4,(undefined4 *)(*(int *)(param_11 + 0x40c) + 0x94));
  }
  if ((*(ushort *)(param_11 + 0x400) & 4) != 0) {
    DAT_803de800 = DAT_803de800 | 8;
  }
  if (*(short *)(param_11 + 0x402) == 1) {
    (**(code **)(**(int **)(iVar4 + 0x68) + 0x28))(iVar4,iVar3,1,2);
    *(undefined *)(iVar3 + 0xe4) = 1;
  }
  else {
    *(undefined *)(iVar3 + 0xe4) = 2;
  }
  *(undefined4 *)(param_11 + 0x3e0) = *(undefined4 *)(iVar3 + 0xc0);
  *(undefined4 *)(iVar3 + 0xc0) = 0;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)FLOAT_803dc074,(double)FLOAT_803dc074,iVar3,param_12,&DAT_803adc78,
             &DAT_803adc60);
  *(undefined4 *)(iVar3 + 0xc0) = *(undefined4 *)(param_11 + 0x3e0);
  FUN_8028688c();
  return;
}

