// Function: FUN_802bf4d8
// Entry: 802bf4d8
// Size: 592 bytes

void FUN_802bf4d8(undefined2 *param_1)

{
  char cVar3;
  int iVar1;
  undefined2 *puVar2;
  int iVar4;
  double dVar5;
  undefined auStack104 [8];
  undefined auStack96 [8];
  undefined auStack88 [8];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined2 local_2c;
  undefined2 local_2a;
  undefined2 local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  longlong local_10;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  cVar3 = FUN_8002e04c();
  if (cVar3 != '\0') {
    FUN_8000bb18(param_1,0x11e);
    iVar1 = FUN_8002bdf4(0x24,0x42a);
    *(undefined *)(iVar1 + 6) = 0xff;
    *(undefined *)(iVar1 + 7) = 0xff;
    *(undefined *)(iVar1 + 4) = 2;
    *(undefined *)(iVar1 + 5) = 1;
    *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(iVar4 + 0xae8);
    *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar4 + 0xaec);
    *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar4 + 0xaf0);
    puVar2 = (undefined2 *)FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
    if (puVar2 != (undefined2 *)0x0) {
      local_20 = FLOAT_803e83a4;
      local_1c = FLOAT_803e83a4;
      local_18 = FLOAT_803e83a4;
      local_24 = FLOAT_803e83a8;
      local_2c = *param_1;
      local_2a = (undefined2)((short)param_1[1] + -400 >> 1);
      local_28 = 0;
      local_38 = FLOAT_803e83a4;
      local_34 = FLOAT_803e83a4;
      local_30 = FLOAT_803e83ac;
      FUN_80021ac8(&local_2c,&local_38);
      *(float *)(puVar2 + 0x12) = local_38;
      *(float *)(puVar2 + 0x14) = local_34;
      *(float *)(puVar2 + 0x16) = local_30;
      local_50 = *(float *)(puVar2 + 6) + FLOAT_803e83b0 * *(float *)(puVar2 + 0x12);
      local_4c = *(float *)(puVar2 + 8) + FLOAT_803e83b0 * *(float *)(puVar2 + 0x14);
      local_48 = *(float *)(puVar2 + 10) + FLOAT_803e83b0 * *(float *)(puVar2 + 0x16);
      FUN_80012d00(param_1 + 0xc,auStack88);
      FUN_80012d00(&local_50,auStack96);
      iVar4 = FUN_800128dc(auStack88,auStack96,auStack104,0,0);
      if (iVar4 == 0) {
        FUN_80012e0c(&local_50,auStack104);
        local_44 = local_50 - *(float *)(puVar2 + 6);
        local_40 = local_4c - *(float *)(puVar2 + 8);
        local_3c = local_48 - *(float *)(puVar2 + 10);
        dVar5 = (double)FUN_802931a0((double)(local_3c * local_3c +
                                             local_44 * local_44 + local_40 * local_40));
      }
      else {
        dVar5 = (double)FLOAT_803e83b4;
      }
      local_10 = (longlong)(int)dVar5;
      *(int *)(puVar2 + 0x7a) = (int)dVar5;
      *(undefined2 **)(puVar2 + 0x7c) = param_1;
      puVar2[2] = 0;
      puVar2[1] = 0;
      *puVar2 = 0;
      (**(code **)(*DAT_803dca88 + 8))(puVar2,0x66,0,2,0xffffffff,0);
    }
  }
  return;
}

