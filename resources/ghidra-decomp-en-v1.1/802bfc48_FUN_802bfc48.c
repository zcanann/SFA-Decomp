// Function: FUN_802bfc48
// Entry: 802bfc48
// Size: 592 bytes

void FUN_802bfc48(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  undefined8 uVar4;
  double dVar5;
  double dVar6;
  short asStack_68 [4];
  short asStack_60 [4];
  short asStack_58 [4];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
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
  longlong local_10;
  
  iVar3 = *(int *)(param_9 + 0x5c);
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    uVar4 = FUN_8000bb38((uint)param_9,0x11e);
    puVar2 = FUN_8002becc(0x24,0x42a);
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    *(undefined *)(puVar2 + 2) = 2;
    *(undefined *)((int)puVar2 + 5) = 1;
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar3 + 0xae8);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar3 + 0xaec);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar3 + 0xaf0);
    puVar2 = (undefined2 *)
             FUN_8002e088(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                          0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
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
      dVar6 = (double)(FLOAT_803e9048 * *(float *)(puVar2 + 0x12));
      dVar5 = (double)(FLOAT_803e9048 * *(float *)(puVar2 + 0x14));
      local_50 = (float)((double)*(float *)(puVar2 + 6) + dVar6);
      local_4c = (float)((double)*(float *)(puVar2 + 8) + dVar5);
      local_48 = *(float *)(puVar2 + 10) + FLOAT_803e9048 * *(float *)(puVar2 + 0x16);
      FUN_80012d20((float *)(param_9 + 0xc),asStack_58);
      uVar4 = FUN_80012d20(&local_50,asStack_60);
      iVar3 = FUN_800128fc(uVar4,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,asStack_58,
                           asStack_60,(undefined4 *)asStack_68,(undefined *)0x0,0);
      if (iVar3 == 0) {
        FUN_80012e2c(&local_50,asStack_68);
        local_44 = local_50 - *(float *)(puVar2 + 6);
        local_40 = local_4c - *(float *)(puVar2 + 8);
        local_3c = local_48 - *(float *)(puVar2 + 10);
        dVar5 = FUN_80293900((double)(local_3c * local_3c +
                                     local_44 * local_44 + local_40 * local_40));
      }
      else {
        dVar5 = (double)FLOAT_803e904c;
      }
      local_10 = (longlong)(int)dVar5;
      *(int *)(puVar2 + 0x7a) = (int)dVar5;
      *(ushort **)(puVar2 + 0x7c) = param_9;
      puVar2[2] = 0;
      puVar2[1] = 0;
      *puVar2 = 0;
      (**(code **)(*DAT_803dd708 + 8))(puVar2,0x66,0,2,0xffffffff,0);
    }
  }
  return;
}

