// Function: FUN_80240708
// Entry: 80240708
// Size: 520 bytes

void FUN_80240708(int param_1,int param_2)

{
  int iVar1;
  float *pfVar2;
  undefined4 uVar3;
  uint uVar4;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  longlong local_20;
  longlong local_18;
  
  local_30 = *(float *)(param_1 + 0xc) - FLOAT_803dd190;
  local_44 = *(float *)(param_1 + 0x10);
  local_34 = *(undefined4 *)(param_1 + 0x14);
  local_3c = *(float *)(param_1 + 0xc) + FLOAT_803dd190;
  local_48 = local_30 - FLOAT_803dda58;
  local_40 = local_30 - FLOAT_803dda5c;
  local_38 = local_44;
  local_2c = local_44;
  local_28 = local_34;
  pfVar2 = (float *)FUN_8000f56c();
  FUN_80247bf8(pfVar2,&local_48,&local_48);
  local_48 = -local_48;
  local_44 = -local_44;
  local_40 = -local_40;
  FUN_80247edc((double)FLOAT_803dd194,&local_48,&local_48);
  pfVar2 = (float *)FUN_8000f560();
  FUN_80247bf8(pfVar2,&local_48,&local_48);
  FUN_80247e94(&local_30,&local_48,&local_30);
  local_48 = local_3c - FLOAT_803dda58;
  local_44 = local_38;
  local_40 = local_3c - FLOAT_803dda5c;
  pfVar2 = (float *)FUN_8000f56c();
  FUN_80247bf8(pfVar2,&local_48,&local_48);
  local_48 = -local_48;
  local_44 = -local_44;
  local_40 = -local_40;
  FUN_80247edc((double)FLOAT_803dd194,&local_48,&local_48);
  pfVar2 = (float *)FUN_8000f560();
  FUN_80247bf8(pfVar2,&local_48,&local_48);
  FUN_80247e94(&local_3c,&local_48,&local_3c);
  if (*(int *)(param_2 + 4) == 0) {
    local_20 = (longlong)(int)FLOAT_803dd188;
    local_18 = (longlong)(int)FLOAT_803dd18c;
    uVar3 = FUN_8008fdac((double)FLOAT_803dd180,(double)FLOAT_803dd184,&local_30,&local_3c,
                         (short)(int)FLOAT_803dd188,(char)(int)FLOAT_803dd18c,0);
    *(undefined4 *)(param_2 + 4) = uVar3;
    *(float *)(param_2 + 8) = FLOAT_803e82a0;
  }
  else {
    *(float *)(param_2 + 8) = *(float *)(param_2 + 8) + FLOAT_803dc074;
    iVar1 = (int)(FLOAT_803e82a4 + *(float *)(param_2 + 8));
    local_18 = (longlong)iVar1;
    *(short *)(*(int *)(param_2 + 4) + 0x20) = (short)iVar1;
    uVar4 = *(uint *)(param_2 + 4);
    if (*(ushort *)(uVar4 + 0x22) <= *(ushort *)(uVar4 + 0x20)) {
      FUN_800238c4(uVar4);
      *(undefined4 *)(param_2 + 4) = 0;
    }
  }
  return;
}

