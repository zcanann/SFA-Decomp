// Function: FUN_80233be4
// Entry: 80233be4
// Size: 428 bytes

void FUN_80233be4(short *param_1)

{
  double dVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined local_48;
  undefined local_47;
  undefined local_46 [6];
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  dVar1 = DOUBLE_803e7238;
  iVar3 = *(int *)(param_1 + 0x26);
  piVar4 = *(int **)(param_1 + 0x5c);
  if (*piVar4 != 0) {
    uStack60 = (int)*(short *)(iVar3 + 0x32) ^ 0x80000000;
    local_40 = 0x43300000;
    uStack52 = (int)*param_1 ^ 0x80000000;
    local_38 = 0x43300000;
    iVar2 = (int)((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7238) * FLOAT_803db414
                 + (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e7238));
    local_30 = (longlong)iVar2;
    *param_1 = (short)iVar2;
    uStack36 = (int)*(short *)(iVar3 + 0x34) ^ 0x80000000;
    local_28 = 0x43300000;
    uStack28 = (int)param_1[1] ^ 0x80000000;
    local_20 = 0x43300000;
    iVar2 = (int)((float)((double)CONCAT44(0x43300000,uStack36) - dVar1) * FLOAT_803db414 +
                 (float)((double)CONCAT44(0x43300000,uStack28) - dVar1));
    local_18 = (longlong)iVar2;
    param_1[1] = (short)iVar2;
    if (*(char *)(piVar4 + 1) == '\0') {
      if ((0 < *(short *)(iVar3 + 0x1e)) && (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
        *(undefined *)(piVar4 + 1) = 1;
        FUN_8001db6c((double)FLOAT_803e7234,*piVar4,1);
      }
    }
    else {
      if ((0 < *(short *)(iVar3 + 0x1e)) && (iVar2 = FUN_8001ffb4(), iVar2 == 0)) {
        *(undefined *)(piVar4 + 1) = 0;
        FUN_8001db6c((double)FLOAT_803e7234,*piVar4,0);
      }
      if ((*(byte *)(iVar3 + 0x2a) & 1) != 0) {
        FUN_800898c8(0,local_46,&local_47,&local_48);
        FUN_8001daf0(*piVar4,local_46[0],local_47,local_48,0xff);
        FUN_8001dab8(*piVar4,local_46[0],local_47,local_48,0xff);
      }
    }
    if (*piVar4 != 0) {
      FUN_8001d6b0();
    }
  }
  return;
}

