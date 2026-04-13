// Function: FUN_801f97f0
// Entry: 801f97f0
// Size: 636 bytes

void FUN_801f97f0(undefined2 *param_1,int param_2)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0x5c);
  FUN_800372f8((int)param_1,3);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  FUN_80037a5c((int)param_1,2);
  puVar2[0x9c] = *(uint *)(param_2 + 8);
  puVar2[0x9d] = *(uint *)(param_2 + 0xc);
  puVar2[0x9e] = *(uint *)(param_2 + 0x10);
  puVar2[0x9a] = (uint)(float)((double)CONCAT44(0x43300000,
                                                (int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                              DOUBLE_803e6cc0);
  *(undefined *)(puVar2 + 0xa6) = *(undefined *)(param_2 + 0x19);
  *(undefined2 *)(puVar2 + 0xa5) =
       *(undefined2 *)(&DAT_80329a10 + (uint)*(byte *)(puVar2 + 0xa6) * 2);
  FUN_800803f8((undefined4 *)((int)puVar2 + 0x28a));
  FUN_800803f8(puVar2 + 0xa3);
  FUN_800803f8(puVar2 + 0xa2);
  if ((*(ushort *)(puVar2 + 0xa5) & 1) == 0) {
    if ((*(ushort *)(puVar2 + 0xa5) & 8) == 0) {
      FUN_80080404((float *)(puVar2 + 0xa2),400);
      param_1[2] = 0x8001;
      *(undefined *)((int)puVar2 + 0x296) = 0;
    }
    else {
      FUN_80080404((float *)((int)puVar2 + 0x28a),0x4b0);
      puVar2[0x9a] = (uint)FLOAT_803e6cc8;
      param_1[2] = 0;
      *(undefined *)((int)puVar2 + 0x296) = 1;
    }
  }
  else {
    param_1[2] = 0;
    *(undefined *)((int)puVar2 + 0x296) = 1;
  }
  if ((*(ushort *)(puVar2 + 0xa5) & 0x40) != 0) {
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  puVar2[0xa1] = (uint)FLOAT_803e6c48;
  *(undefined2 *)((int)puVar2 + 0x28e) = *(undefined2 *)(param_2 + 0x1c);
  *(float *)(param_1 + 8) =
       *(float *)(param_2 + 0xc) +
       (float)((double)CONCAT44(0x43300000,(int)*(short *)((int)puVar2 + 0x28e) ^ 0x80000000) -
              DOUBLE_803e6cc0);
  uVar1 = FUN_80022264(0,0x50);
  *(short *)(puVar2 + 0xa4) = (short)uVar1 + 400;
  puVar2[0x9b] = (uint)FLOAT_803e6ccc;
  *(undefined2 *)((int)puVar2 + 0x292) = *(undefined2 *)(param_2 + 0x1e);
  if ((*(ushort *)(puVar2 + 0xa5) & 2) != 0) {
    *(undefined *)((int)puVar2 + 0x25b) = 1;
    (**(code **)(*DAT_803dd728 + 4))(puVar2,0,0,1);
    (**(code **)(*DAT_803dd728 + 8))(puVar2,1,&DAT_80329a20,&DAT_803dcd9c,4);
    (**(code **)(*DAT_803dd728 + 0x20))(param_1,puVar2);
    *puVar2 = *puVar2 | 0x40008;
  }
  *(undefined **)(param_1 + 0x5e) = &LAB_801f862c;
  FUN_80036018((int)param_1);
  FUN_80035f9c((int)param_1);
  return;
}

