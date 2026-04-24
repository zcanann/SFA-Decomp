// Function: FUN_801a0310
// Entry: 801a0310
// Size: 408 bytes

void FUN_801a0310(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  byte local_58;
  byte local_57;
  byte local_56 [2];
  float local_54;
  float local_50;
  float local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  undefined4 local_28;
  uint uStack36;
  longlong local_20;
  undefined4 local_18;
  uint uStack20;
  longlong local_10;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  if (*piVar4 == 0) {
    iVar3 = FUN_8001cc9c(param_1,0xfa,0xfa,0xfa,1);
    *piVar4 = iVar3;
    if (*piVar4 != 0) {
      FUN_8001dc38((double)FLOAT_803dbe58,
                   (double)(float)((double)FLOAT_803e42a0 + (double)FLOAT_803dbe58));
    }
  }
  FUN_80035df4(param_1,0x17,0,0);
  local_48 = DAT_80322c38;
  local_44 = DAT_80322c3c;
  local_40 = DAT_80322c40;
  FUN_8002b198(param_1,&DAT_80322c38,&local_48);
  FUN_80221dc0((double)FLOAT_803dbe5c,&local_54,param_1 + 0xc,&local_48);
  FUN_80247984(param_1 + 0xc,&local_54);
  FUN_80247778(&DAT_80322c38,&local_54);
  FUN_800898c8(0,local_56,&local_57,&local_58);
  if (*piVar4 != 0) {
    uStack52 = (uint)local_56[0];
    local_38 = 0x43300000;
    iVar3 = (int)(FLOAT_803e42a4 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e42a8))
    ;
    local_30 = (longlong)iVar3;
    uStack36 = (uint)local_57;
    local_28 = 0x43300000;
    iVar1 = (int)(FLOAT_803e42a4 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e42a8))
    ;
    local_20 = (longlong)iVar1;
    uStack20 = (uint)local_58;
    local_18 = 0x43300000;
    iVar2 = (int)(FLOAT_803e42a4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e42a8))
    ;
    local_10 = (longlong)iVar2;
    FUN_8001daf0(*piVar4,iVar3,iVar1,iVar2,0xff);
    FUN_8001dd88((double)local_54,(double)local_50,(double)local_4c,*piVar4);
  }
  return;
}

