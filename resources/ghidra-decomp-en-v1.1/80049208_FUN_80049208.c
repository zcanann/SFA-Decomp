// Function: FUN_80049208
// Entry: 80049208
// Size: 184 bytes

int FUN_80049208(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,uint param_10,undefined4 param_11,undefined4 param_12,
                undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int aiStack_58 [13];
  int local_24;
  
  if ((&DAT_80360048)[param_9] == 0) {
    FUN_80249300(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (&PTR_s_AUDIO_tab_802cbecc)[param_9],(int)aiStack_58);
    FUN_802420b0(param_10,local_24);
    FUN_80015888(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,param_10
                 ,local_24,0,param_13,param_14,param_15,param_16);
    FUN_802493c8(aiStack_58);
  }
  else {
    FUN_80003494(param_10,(&DAT_80360048)[param_9],(&DAT_8035fd08)[param_9]);
    FUN_80242114(param_10,(&DAT_8035fd08)[param_9]);
    local_24 = (&DAT_8035fd08)[param_9];
  }
  return local_24;
}

