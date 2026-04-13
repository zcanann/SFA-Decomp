// Function: FUN_80120028
// Entry: 80120028
// Size: 200 bytes

void FUN_80120028(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  
  if (DAT_803de450 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)FUN_80023d8c(0x48,0x19);
    uVar3 = 0;
    uVar4 = 0x48;
    FUN_800033a8((int)puVar1,0,0x48);
    *puVar1 = 0;
    puVar1[1] = param_9;
    uVar2 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_10,
                         uVar3,uVar4,param_12,param_13,param_14,param_15,param_16);
    puVar1[0xb] = uVar2;
    uVar2 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_11,
                         uVar3,uVar4,param_12,param_13,param_14,param_15,param_16);
    puVar1[0xc] = uVar2;
    puVar1[4] = (uint)*(ushort *)(puVar1[0xb] + 10);
    puVar1[5] = (uint)*(ushort *)(puVar1[0xb] + 0xc);
    DAT_803de450 = puVar1;
    *(undefined *)(puVar1 + 6) = 0;
    puVar1[9] = FLOAT_803e2ae8;
    puVar1[0x10] = 0;
  }
  return;
}

