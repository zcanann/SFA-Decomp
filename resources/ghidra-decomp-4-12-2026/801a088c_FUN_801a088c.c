// Function: FUN_801a088c
// Entry: 801a088c
// Size: 408 bytes

void FUN_801a088c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  double dVar5;
  byte local_58;
  byte local_57;
  byte local_56 [2];
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  longlong local_20;
  undefined4 local_18;
  uint uStack_14;
  longlong local_10;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  if (*piVar4 == 0) {
    iVar3 = FUN_8001cd60(param_9,0xfa,0xfa,0xfa,1);
    *piVar4 = iVar3;
    if (*piVar4 != 0) {
      param_2 = (double)(float)((double)FLOAT_803e4f38 + (double)FLOAT_803dcac0);
      FUN_8001dcfc((double)FLOAT_803dcac0,param_2,*piVar4);
    }
  }
  FUN_80035eec((int)param_9,0x17,0,0);
  local_48 = DAT_80323888;
  local_44 = DAT_8032388c;
  local_40 = DAT_80323890;
  FUN_8002b270(param_9,&DAT_80323888,&local_48);
  FUN_80222410((double)FLOAT_803dcac4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               &local_54,(float *)(param_9 + 6),&local_48);
  dVar5 = FUN_802480e8((float *)(param_9 + 6),&local_54);
  FUN_80247edc(dVar5,&DAT_80323888,&local_54);
  FUN_80089b54(0,local_56,&local_57,&local_58);
  if (*piVar4 != 0) {
    uStack_34 = (uint)local_56[0];
    local_38 = 0x43300000;
    iVar3 = (int)(FLOAT_803e4f3c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4f40)
                 );
    local_30 = (longlong)iVar3;
    uStack_24 = (uint)local_57;
    local_28 = 0x43300000;
    iVar1 = (int)(FLOAT_803e4f3c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4f40)
                 );
    local_20 = (longlong)iVar1;
    uStack_14 = (uint)local_58;
    local_18 = 0x43300000;
    iVar2 = (int)(FLOAT_803e4f3c * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e4f40)
                 );
    local_10 = (longlong)iVar2;
    FUN_8001dbb4(*piVar4,(char)iVar3,(char)iVar1,(char)iVar2,0xff);
    FUN_8001de4c((double)local_54,(double)local_50,(double)local_4c,(int *)*piVar4);
  }
  return;
}

