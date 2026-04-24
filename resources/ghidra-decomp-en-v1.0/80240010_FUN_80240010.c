// Function: FUN_80240010
// Entry: 80240010
// Size: 520 bytes

void FUN_80240010(int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
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
  
  local_30 = *(float *)(param_1 + 0xc) - FLOAT_803dc528;
  local_44 = *(float *)(param_1 + 0x10);
  local_34 = *(undefined4 *)(param_1 + 0x14);
  local_3c = *(float *)(param_1 + 0xc) + FLOAT_803dc528;
  local_48 = local_30 - FLOAT_803dcdd8;
  local_40 = local_30 - FLOAT_803dcddc;
  local_38 = local_44;
  local_2c = local_44;
  local_28 = local_34;
  uVar2 = FUN_8000f54c();
  FUN_80247494(uVar2,&local_48,&local_48);
  local_48 = -local_48;
  local_44 = -local_44;
  local_40 = -local_40;
  FUN_80247778((double)FLOAT_803dc52c,&local_48,&local_48);
  uVar2 = FUN_8000f540();
  FUN_80247494(uVar2,&local_48,&local_48);
  FUN_80247730(&local_30,&local_48,&local_30);
  local_48 = local_3c - FLOAT_803dcdd8;
  local_44 = local_38;
  local_40 = local_3c - FLOAT_803dcddc;
  uVar2 = FUN_8000f54c();
  FUN_80247494(uVar2,&local_48,&local_48);
  local_48 = -local_48;
  local_44 = -local_44;
  local_40 = -local_40;
  FUN_80247778((double)FLOAT_803dc52c,&local_48,&local_48);
  uVar2 = FUN_8000f540();
  FUN_80247494(uVar2,&local_48,&local_48);
  FUN_80247730(&local_3c,&local_48,&local_3c);
  if (*(int *)(param_2 + 4) == 0) {
    local_20 = (longlong)(int)FLOAT_803dc520;
    local_18 = (longlong)(int)FLOAT_803dc524;
    uVar2 = FUN_8008fb20((double)FLOAT_803dc518,(double)FLOAT_803dc51c,&local_30,&local_3c,
                         (int)FLOAT_803dc520,(int)FLOAT_803dc524,0);
    *(undefined4 *)(param_2 + 4) = uVar2;
    *(float *)(param_2 + 8) = FLOAT_803e7608;
  }
  else {
    *(float *)(param_2 + 8) = *(float *)(param_2 + 8) + FLOAT_803db414;
    iVar1 = (int)(FLOAT_803e760c + *(float *)(param_2 + 8));
    local_18 = (longlong)iVar1;
    *(short *)(*(int *)(param_2 + 4) + 0x20) = (short)iVar1;
    if (*(ushort *)(*(int *)(param_2 + 4) + 0x22) <= *(ushort *)(*(int *)(param_2 + 4) + 0x20)) {
      FUN_80023800();
      *(undefined4 *)(param_2 + 4) = 0;
    }
  }
  return;
}

