// Function: FUN_802bfecc
// Entry: 802bfecc
// Size: 472 bytes

undefined4
FUN_802bfecc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  float local_38;
  float local_34;
  float local_30;
  ushort local_2c;
  undefined2 local_2a;
  undefined2 local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  iVar4 = *(int *)(param_9 + 0x5c);
  iVar3 = *(int *)(param_9 + 0x2a);
  *param_10 = *param_10 | 0x200000;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(byte *)(iVar4 + 0xbb6) = *(byte *)(iVar4 + 0xbb6) & 0xf7;
    *(ushort *)(iVar3 + 0x60) = *(ushort *)(iVar3 + 0x60) | 0x200;
    FUN_8003042c((double)FLOAT_803e903c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xd,0,param_12,param_13,param_14,param_15,param_16);
    param_10[0xa8] = (uint)FLOAT_803e9050;
    uVar1 = FUN_8002e144();
    if ((uVar1 & 0xff) != 0) {
      uVar5 = FUN_8000bb38((uint)param_9,0x11e);
      puVar2 = FUN_8002becc(0x18,0x42a);
      *(undefined *)(puVar2 + 3) = 0xff;
      *(undefined *)((int)puVar2 + 7) = 0xff;
      *(undefined *)(puVar2 + 2) = 2;
      *(undefined *)((int)puVar2 + 5) = 1;
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0xae8);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0xaec);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0xaf0);
      puVar2 = (undefined2 *)
               FUN_8002e088(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                            0xff,0xffffffff,(uint *)0x0,param_14,param_15,param_16);
      if (puVar2 != (undefined2 *)0x0) {
        local_20 = FLOAT_803e903c;
        local_1c = FLOAT_803e903c;
        local_18 = FLOAT_803e903c;
        local_24 = FLOAT_803e9040;
        local_2c = *param_9;
        local_2a = (undefined2)((short)param_9[1] + -400 >> 1);
        local_28 = 0;
        local_38 = FLOAT_803e903c;
        local_34 = FLOAT_803e903c;
        local_30 = FLOAT_803e9044;
        FUN_80021b8c(&local_2c,&local_38);
        *(float *)(puVar2 + 0x12) = local_38;
        *(float *)(puVar2 + 0x14) = local_34;
        *(float *)(puVar2 + 0x16) = local_30;
        *(undefined4 *)(puVar2 + 0x7a) = 0xb4;
        *(ushort **)(puVar2 + 0x7c) = param_9;
        puVar2[2] = 0;
        puVar2[1] = 0;
        *puVar2 = 0;
        (**(code **)(*DAT_803dd708 + 8))(puVar2,0x66,0,2,0xffffffff,0);
      }
    }
  }
  return 0;
}

