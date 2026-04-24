// Function: FUN_800492c0
// Entry: 800492c0
// Size: 188 bytes

int FUN_800492c0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9)

{
  int iVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int aiStack_58 [13];
  undefined4 local_24;
  
  iVar1 = (&DAT_80360048)[param_9];
  if (iVar1 == 0) {
    FUN_80249300(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (&PTR_s_AUDIO_tab_802cbecc)[param_9],(int)aiStack_58);
    (&DAT_8035fd08)[param_9] = local_24;
    iVar1 = FUN_80023d8c((&DAT_8035fd08)[param_9] + 0x20,0x7d7d7d7d);
    (&DAT_80360048)[param_9] = iVar1;
    FUN_802420b0((&DAT_80360048)[param_9],(&DAT_8035fd08)[param_9]);
    FUN_80015888(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,
                 (&DAT_80360048)[param_9],(&DAT_8035fd08)[param_9],0,in_r7,in_r8,in_r9,in_r10);
    FUN_802493c8(aiStack_58);
    iVar1 = (&DAT_80360048)[param_9];
  }
  return iVar1;
}

