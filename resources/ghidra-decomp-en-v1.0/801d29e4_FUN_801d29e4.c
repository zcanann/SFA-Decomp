// Function: FUN_801d29e4
// Entry: 801d29e4
// Size: 336 bytes

void FUN_801d29e4(undefined2 *param_1)

{
  char cVar2;
  int iVar1;
  int iVar3;
  float local_78;
  float local_74;
  float local_70;
  undefined2 local_6c;
  undefined2 local_6a;
  undefined2 local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  undefined auStack84 [72];
  
  iVar3 = *(int *)(param_1 + 0x26);
  cVar2 = FUN_8002e04c();
  if (cVar2 != '\0') {
    iVar1 = FUN_8002bdf4(0x24,0x198);
    local_6c = *param_1;
    local_6a = param_1[1];
    local_68 = param_1[2];
    local_60 = FLOAT_803e536c;
    local_5c = FLOAT_803e536c;
    local_58 = FLOAT_803e536c;
    local_64 = FLOAT_803e5370;
    FUN_80021ee8(auStack84,&local_6c);
    FUN_800226cc((double)FLOAT_803e536c,(double)FLOAT_803e5370,(double)FLOAT_803e536c,auStack84,
                 &local_78,&local_74,&local_70);
    local_60 = FLOAT_803e5374 * local_78;
    local_5c = FLOAT_803e5374 * local_74;
    local_58 = FLOAT_803e5374 * local_70;
    *(float *)(iVar1 + 8) = *(float *)(param_1 + 6) + local_60;
    *(float *)(iVar1 + 0xc) = *(float *)(param_1 + 8) + local_5c;
    *(float *)(iVar1 + 0x10) = *(float *)(param_1 + 10) + local_58;
    *(undefined *)(iVar1 + 5) = 1;
    *(undefined *)(iVar1 + 4) = 2;
    *(short *)(iVar1 + 0x1a) = (short)((int)*(char *)(iVar3 + 0x1e) << 8);
    *(undefined2 *)(iVar1 + 0x1c) = *param_1;
    FUN_8002df90(iVar1,5,0xffffffff,0xffffffff,0);
  }
  return;
}

