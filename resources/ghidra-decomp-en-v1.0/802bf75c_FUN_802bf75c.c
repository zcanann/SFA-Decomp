// Function: FUN_802bf75c
// Entry: 802bf75c
// Size: 472 bytes

undefined4 FUN_802bf75c(undefined2 *param_1,uint *param_2)

{
  char cVar2;
  undefined2 *puVar1;
  int iVar3;
  int iVar4;
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
  
  iVar4 = *(int *)(param_1 + 0x5c);
  iVar3 = *(int *)(param_1 + 0x2a);
  *param_2 = *param_2 | 0x200000;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(byte *)(iVar4 + 0xbb6) = *(byte *)(iVar4 + 0xbb6) & 0xf7;
    *(ushort *)(iVar3 + 0x60) = *(ushort *)(iVar3 + 0x60) | 0x200;
    FUN_80030334((double)FLOAT_803e83a4,param_1,0xd,0);
    param_2[0xa8] = (uint)FLOAT_803e83b8;
    cVar2 = FUN_8002e04c();
    if (cVar2 != '\0') {
      FUN_8000bb18(param_1,0x11e);
      iVar3 = FUN_8002bdf4(0x18,0x42a);
      *(undefined *)(iVar3 + 6) = 0xff;
      *(undefined *)(iVar3 + 7) = 0xff;
      *(undefined *)(iVar3 + 4) = 2;
      *(undefined *)(iVar3 + 5) = 1;
      *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar4 + 0xae8);
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar4 + 0xaec);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar4 + 0xaf0);
      puVar1 = (undefined2 *)FUN_8002df90(iVar3,5,0xffffffff,0xffffffff,0);
      if (puVar1 != (undefined2 *)0x0) {
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
        *(float *)(puVar1 + 0x12) = local_38;
        *(float *)(puVar1 + 0x14) = local_34;
        *(float *)(puVar1 + 0x16) = local_30;
        *(undefined4 *)(puVar1 + 0x7a) = 0xb4;
        *(undefined2 **)(puVar1 + 0x7c) = param_1;
        puVar1[2] = 0;
        puVar1[1] = 0;
        *puVar1 = 0;
        (**(code **)(*DAT_803dca88 + 8))(puVar1,0x66,0,2,0xffffffff,0);
      }
    }
  }
  return 0;
}

