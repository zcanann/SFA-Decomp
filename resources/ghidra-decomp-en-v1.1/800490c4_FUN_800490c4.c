// Function: FUN_800490c4
// Entry: 800490c4
// Size: 324 bytes

void FUN_800490c4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  ulonglong uVar6;
  int aiStack_58 [22];
  
  uVar6 = FUN_80286840();
  iVar2 = (int)(uVar6 >> 0x20);
  uVar4 = (uint)uVar6;
  if (param_12 != 0) {
    if ((&DAT_80360048)[iVar2] == 0) {
      uVar5 = extraout_f1;
      FUN_80249300(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (&PTR_s_AUDIO_tab_802cbecc)[iVar2],(int)aiStack_58);
      if (((uVar6 & 0x1f) == 0) && ((param_12 & 0x1f) == 0)) {
        FUN_802420b0(uVar4,param_12);
        FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,uVar4,
                     param_12,param_11,param_13,param_14,param_15,param_16);
      }
      else {
        uVar1 = param_12 + 0x1f & 0xffffffe0;
        uVar3 = FUN_80023d8c(uVar1,0x7d7d7d7d);
        FUN_802420b0(uVar3,uVar1);
        FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,uVar3,
                     uVar1,param_11,param_13,param_14,param_15,param_16);
        FUN_80003494(uVar4,uVar3,param_12);
        FUN_800238c4(uVar3);
      }
      FUN_802493c8(aiStack_58);
      FUN_80242114(uVar4,param_12);
    }
    else {
      FUN_80003494(uVar4,(&DAT_80360048)[iVar2] + param_11,param_12);
      FUN_80242114(uVar4,param_12);
    }
  }
  FUN_8028688c();
  return;
}

