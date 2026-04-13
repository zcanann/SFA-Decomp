// Function: FUN_802732c0
// Entry: 802732c0
// Size: 360 bytes

void FUN_802732c0(uint param_1,int param_2,undefined4 param_3,char param_4,uint param_5,int param_6,
                 undefined4 param_7,char param_8,uint param_9)

{
  uint uVar1;
  uint uVar2;
  
  FUN_80285258();
  if (param_2 == 0) {
    (&DAT_803be624)[param_1 & 0xff] = 0;
    (&DAT_803deed4)[param_1 & 0xff] = 0xff;
  }
  else {
    uVar1 = param_1 & 0xff;
    (&DAT_803deed4)[uVar1] = param_4;
    if (param_4 != -1) {
      uVar2 = FUN_8026cb80(param_5);
      (&DAT_803deecc)[uVar1] = (char)uVar2;
      (&DAT_803be624)[uVar1] = param_2;
      (&DAT_803be604)[uVar1] = param_3;
    }
  }
  if (param_6 == 0) {
    (&DAT_803be664)[param_1 & 0xff] = 0;
    (&DAT_803deec4)[param_1 & 0xff] = 0xff;
  }
  else {
    uVar1 = param_1 & 0xff;
    (&DAT_803deec4)[uVar1] = param_8;
    if (param_8 != -1) {
      uVar2 = FUN_8026cb80(param_9);
      (&DAT_803deebc)[uVar1] = (char)uVar2;
      (&DAT_803be664)[uVar1] = param_6;
      (&DAT_803be644)[uVar1] = param_7;
    }
  }
  FUN_8028429c(param_1,param_2,param_3,param_6,param_7);
  FUN_80285220();
  return;
}

