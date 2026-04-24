// Function: FUN_801511e8
// Entry: 801511e8
// Size: 452 bytes

void FUN_801511e8(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined *puVar2;
  
  puVar2 = (&PTR_DAT_8031f178)[(uint)*(byte *)(param_2 + 0x33b) * 10];
  if (FLOAT_803e27a4 * *(float *)(param_2 + 0x2ac) <
      (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a4)) - DOUBLE_803e2770)) {
    if ((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a4)) - DOUBLE_803e2770)
        <= FLOAT_803e27a8 * *(float *)(param_2 + 0x2ac)) {
      *(char *)(param_2 + 0x33a) = puVar2[8] + '\x03';
    }
    else {
      *(char *)(param_2 + 0x33a) = puVar2[8] + '\x02';
    }
  }
  while( true ) {
    if ((*(uint *)(puVar2 + (uint)*(byte *)(param_2 + 0x33a) * 0x10 + 4) == 0) ||
       ((*(uint *)(param_2 + 0x2dc) &
        *(uint *)(puVar2 + (uint)*(byte *)(param_2 + 0x33a) * 0x10 + 4)) != 0)) break;
    *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
    if ((byte)puVar2[8] < *(byte *)(param_2 + 0x33a)) {
      *(undefined *)(param_2 + 0x33a) = 1;
    }
  }
  *(undefined *)(param_2 + 0x2f2) = puVar2[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 10];
  *(undefined *)(param_2 + 0x2f3) = puVar2[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 0xb];
  *(undefined *)(param_2 + 0x2f4) = puVar2[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 0xc];
  iVar1 = (uint)*(byte *)(param_2 + 0x33a) * 0x10;
  FUN_8014d08c((double)*(float *)(puVar2 + iVar1),param_1,param_2,puVar2[iVar1 + 8],0,3);
  FUN_80030304((double)*(float *)(&DAT_8031dd30 +
                                 (uint)(byte)puVar2[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 8] * 4
                                 ),param_1);
  *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
  if ((byte)puVar2[8] < *(byte *)(param_2 + 0x33a)) {
    *(undefined *)(param_2 + 0x33a) = 1;
  }
  return;
}

