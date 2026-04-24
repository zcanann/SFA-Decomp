// Function: FUN_80086050
// Entry: 80086050
// Size: 660 bytes

short * FUN_80086050(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                    undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
                    int *param_10,int param_11,int *param_12,int *param_13,int param_14,
                    int *param_15,int param_16)

{
  short *psVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  float local_18 [2];
  
  *(byte *)((int)param_10 + 0x79) = *(byte *)((int)param_10 + 0x79) ^ 1;
  if (*(char *)((int)param_10 + 0x79) == '\0') {
    if (*param_10 != 0) {
      if ((*(ushort *)((int)param_10 + 0x6e) & 1) != 0) {
        *(undefined4 *)(param_9 + 6) = *(undefined4 *)(param_9 + 6);
        *(undefined4 *)(param_9 + 8) = *(undefined4 *)(param_9 + 8);
        *(undefined4 *)(param_9 + 10) = *(undefined4 *)(param_9 + 10);
        FUN_80084c74((int)param_9,(int)param_10);
      }
      if ((*(char *)((int)param_10 + 0x7a) == '\x01') &&
         (iVar3 = FUN_80065a20((double)*(float *)(param_9 + 6),(double)*(float *)(param_9 + 8),
                               (double)*(float *)(param_9 + 10),param_9,local_18,0), iVar3 == 0)) {
        *(float *)(param_9 + 8) =
             *(float *)(param_9 + 8) +
             ((*(float *)(param_9 + 8) - local_18[0]) - *(float *)(param_11 + 0xc));
      }
      if ((*(ushort *)((int)param_10 + 0x6e) & 2) != 0) {
        *param_9 = *param_9 + *(short *)((int)param_10 + 0x1a);
      }
      param_9[0x60] = 0;
      param_9[0x61] = 0;
      param_9[0x58] = param_9[0x58] & 0xefff;
      *param_10 = 0;
    }
  }
  else {
    FUN_80081bf8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                 param_10,param_11,param_12,param_13,param_14,param_15,param_16);
    psVar1 = (short *)*param_10;
    if (psVar1 != (short *)0x0) {
      *(short **)(psVar1 + 0x60) = param_9;
      psVar1[0x58] = psVar1[0x58] | 0x1000;
      param_10[0x44] = (int)psVar1;
      iVar6 = *param_10;
      iVar4 = 0;
      iVar3 = *(char *)((int)param_10 + 0x57) * 0x80;
      iVar7 = 2;
      piVar2 = (int *)(&DAT_80397578 + iVar3);
      while ((iVar5 = iVar4, *piVar2 != 0 && (*piVar2 != iVar6))) {
        iVar5 = iVar4 + 1;
        if ((piVar2[2] == 0) || (piVar2[2] == iVar6)) break;
        iVar5 = iVar4 + 2;
        if ((piVar2[4] == 0) || (piVar2[4] == iVar6)) break;
        iVar5 = iVar4 + 3;
        if ((piVar2[6] == 0) || (piVar2[6] == iVar6)) break;
        iVar5 = iVar4 + 4;
        if ((piVar2[8] == 0) || (piVar2[8] == iVar6)) break;
        iVar5 = iVar4 + 5;
        if ((piVar2[10] == 0) || (piVar2[10] == iVar6)) break;
        iVar5 = iVar4 + 6;
        if ((piVar2[0xc] == 0) || (piVar2[0xc] == iVar6)) break;
        iVar5 = iVar4 + 7;
        if ((piVar2[0xe] == 0) || (piVar2[0xe] == iVar6)) break;
        piVar2 = piVar2 + 0x10;
        iVar4 = iVar4 + 8;
        iVar7 = iVar7 + -1;
        iVar5 = iVar4;
        if (iVar7 == 0) break;
      }
      *(int *)((int)(&DAT_80397578 + iVar3) + iVar5 * 2 * 4) = iVar6;
      *(short **)(&DAT_8039757c + iVar3 + iVar5 * 8) = param_9;
      param_9 = psVar1;
    }
  }
  return param_9;
}

