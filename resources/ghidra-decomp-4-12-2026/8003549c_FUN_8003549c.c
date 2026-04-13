// Function: FUN_8003549c
// Entry: 8003549c
// Size: 652 bytes

void FUN_8003549c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,float *param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  bool bVar4;
  undefined4 *puVar3;
  undefined4 uVar5;
  float *pfVar6;
  undefined4 *puVar7;
  float *pfVar8;
  ushort *puVar9;
  undefined8 uVar10;
  int local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined2 local_34;
  undefined2 local_32;
  undefined2 local_30;
  float local_2c;
  float local_28;
  undefined4 uStack_24;
  float local_20 [8];
  
  uVar10 = FUN_8028683c();
  uVar1 = (uint)((ulonglong)uVar10 >> 0x20);
  local_44 = DAT_802c2280;
  local_40 = DAT_802c2284;
  local_3c = DAT_802c2288;
  local_38 = DAT_802c228c;
  if ((param_12 & 0xff) != 0) {
    FUN_8007d858();
    param_2 = (double)FLOAT_803dc074;
    iVar2 = FUN_8002fb40((double)*param_13,param_2);
    if (iVar2 != 0) {
      FUN_8007d858();
      param_12 = 0;
    }
  }
  uVar5 = 0;
  pfVar6 = &local_28;
  puVar7 = &uStack_24;
  pfVar8 = local_20;
  iVar2 = FUN_80036868(uVar1,(undefined4 *)0x0,&local_48,(uint *)0x0,pfVar6,puVar7,pfVar8);
  if (iVar2 != 0) {
    local_28 = local_28 + FLOAT_803dda58;
    local_20[0] = local_20[0] + FLOAT_803dda5c;
    local_2c = FLOAT_803df598;
    local_30 = 0;
    local_32 = 0;
    local_34 = 0;
    local_48 = (int)*(char *)(*(int *)(**(int **)(*(int *)(uVar1 + 0x7c) +
                                                 *(char *)(uVar1 + 0xad) * 4) + 0x58) +
                              local_48 * 0x18 + 0x16);
    if ((int)(param_11 & 0xff) <= local_48) {
      FUN_8007d858();
      local_48 = 0;
    }
    puVar9 = (ushort *)((int)uVar10 + local_48 * 0x14);
    if (iVar2 != 0x11) {
      if ((-1 < (short)*puVar9) && (bVar4 = FUN_8000b5f0(uVar1,*puVar9), !bVar4)) {
        FUN_8000bb38(uVar1,*puVar9);
      }
      if ((-1 < (short)puVar9[1]) && (bVar4 = FUN_8000b5f0(uVar1,puVar9[1]), !bVar4)) {
        FUN_8000bb38(uVar1,puVar9[1]);
      }
      if (*(char *)(puVar9 + 4) == '\x01') {
        puVar3 = (undefined4 *)FUN_80013ee8(0x5a);
        uVar5 = 0x401;
        pfVar6 = (float *)0xffffffff;
        puVar7 = &local_44;
        pfVar8 = (float *)*puVar3;
        (*(code *)pfVar8[1])(0,1,&local_34);
        if (puVar3 != (undefined4 *)0x0) {
          FUN_80013e4c((undefined *)puVar3);
        }
      }
      else {
        uVar5 = 0;
        FUN_8009a468(uVar1,&local_34,1,(int *)0x0);
      }
    }
    if (((param_12 & 0xff) == 0) && (-1 < (short)puVar9[2])) {
      FUN_8003042c((double)FLOAT_803df590,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   uVar1,(int)(short)puVar9[2],0,uVar5,pfVar6,puVar7,pfVar8,param_16);
      *param_13 = *(float *)(puVar9 + 6);
    }
  }
  FUN_80286888();
  return;
}

