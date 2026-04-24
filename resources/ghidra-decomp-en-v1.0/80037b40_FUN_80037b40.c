// Function: FUN_80037b40
// Entry: 80037b40
// Size: 368 bytes

void FUN_80037b40(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5,
                 uint param_6,float *param_7)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  undefined8 uVar4;
  int local_58;
  uint local_54;
  uint local_50;
  uint local_4c;
  uint local_48;
  undefined2 local_44;
  undefined2 local_42;
  undefined2 local_40;
  float local_3c;
  float local_38;
  undefined auStack52 [4];
  float local_30 [12];
  
  uVar4 = FUN_802860d0();
  uVar1 = (undefined4)((ulonglong)uVar4 >> 0x20);
  *param_7 = *param_7 - FLOAT_803db414;
  iVar2 = FUN_80036770(uVar1,&local_58,0,0,&local_38,auStack52,local_30);
  if ((((*param_7 <= FLOAT_803de970) && (iVar2 != 0)) && (*param_7 = FLOAT_803de978, iVar2 != 0x1a))
     && (iVar2 != 5)) {
    local_38 = local_38 + FLOAT_803dcdd8;
    local_30[0] = local_30[0] + FLOAT_803dcddc;
    local_3c = FLOAT_803de97c;
    local_40 = 0;
    local_42 = 0;
    local_44 = 0;
    piVar3 = (int *)FUN_80013ec8(0x5a,1);
    local_54 = (uint)uVar4 & 0xff;
    local_50 = param_3 & 0xff;
    local_4c = param_4 & 0xff;
    local_48 = param_5 & 0xff;
    (**(code **)(*piVar3 + 4))(0,1,&local_44,0x401,0xffffffff,&local_54);
    if ((((param_6 & 0xffff) != 0) && (local_58 != 0)) && (*(short *)(local_58 + 0x46) == 0x69)) {
      FUN_8000bb18(uVar1,param_6);
    }
  }
  FUN_8028611c(iVar2);
  return;
}

