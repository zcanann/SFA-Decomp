// Function: FUN_80037c38
// Entry: 80037c38
// Size: 368 bytes

void FUN_80037c38(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5,
                 uint param_6,float *param_7)

{
  uint uVar1;
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
  undefined4 uStack_34;
  float local_30 [12];
  
  uVar4 = FUN_80286834();
  uVar1 = (uint)((ulonglong)uVar4 >> 0x20);
  *param_7 = *param_7 - FLOAT_803dc074;
  iVar2 = FUN_80036868(uVar1,&local_58,(int *)0x0,(uint *)0x0,&local_38,&uStack_34,local_30);
  if ((((*param_7 <= FLOAT_803df5f0) && (iVar2 != 0)) && (*param_7 = FLOAT_803df5f8, iVar2 != 0x1a))
     && (iVar2 != 5)) {
    local_38 = local_38 + FLOAT_803dda58;
    local_30[0] = local_30[0] + FLOAT_803dda5c;
    local_3c = FLOAT_803df5fc;
    local_40 = 0;
    local_42 = 0;
    local_44 = 0;
    piVar3 = (int *)FUN_80013ee8(0x5a);
    local_54 = (uint)uVar4 & 0xff;
    local_50 = param_3 & 0xff;
    local_4c = param_4 & 0xff;
    local_48 = param_5 & 0xff;
    (**(code **)(*piVar3 + 4))(0,1,&local_44,0x401,0xffffffff,&local_54);
    if ((((param_6 & 0xffff) != 0) && (local_58 != 0)) && (*(short *)(local_58 + 0x46) == 0x69)) {
      FUN_8000bb38(uVar1,(ushort)param_6);
    }
  }
  FUN_80286880();
  return;
}

