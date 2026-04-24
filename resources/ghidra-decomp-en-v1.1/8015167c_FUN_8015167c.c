// Function: FUN_8015167c
// Entry: 8015167c
// Size: 452 bytes

void FUN_8015167c(int param_1,int param_2)

{
  int iVar1;
  double dVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar3;
  double dVar4;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  dVar2 = DOUBLE_803e3408;
  puVar3 = (&PTR_DAT_8031fdc8)[(uint)*(byte *)(param_2 + 0x33b) * 10];
  dVar4 = (double)*(float *)(param_2 + 0x2ac);
  if ((float)((double)FLOAT_803e343c * dVar4) <
      (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a4)) - DOUBLE_803e3408)) {
    if ((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x2a4)) - DOUBLE_803e3408)
        <= (float)((double)FLOAT_803e3440 * dVar4)) {
      *(char *)(param_2 + 0x33a) = puVar3[8] + '\x03';
    }
    else {
      *(char *)(param_2 + 0x33a) = puVar3[8] + '\x02';
    }
  }
  while( true ) {
    if ((*(uint *)(puVar3 + (uint)*(byte *)(param_2 + 0x33a) * 0x10 + 4) == 0) ||
       ((*(uint *)(param_2 + 0x2dc) &
        *(uint *)(puVar3 + (uint)*(byte *)(param_2 + 0x33a) * 0x10 + 4)) != 0)) break;
    *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
    if ((byte)puVar3[8] < *(byte *)(param_2 + 0x33a)) {
      *(undefined *)(param_2 + 0x33a) = 1;
    }
  }
  *(undefined *)(param_2 + 0x2f2) = puVar3[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 10];
  *(undefined *)(param_2 + 0x2f3) = puVar3[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 0xb];
  *(undefined *)(param_2 + 0x2f4) = puVar3[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 0xc];
  iVar1 = (uint)*(byte *)(param_2 + 0x33a) * 0x10;
  FUN_8014d504((double)*(float *)(puVar3 + iVar1),dVar2,dVar4,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,
               param_2,(uint)(byte)puVar3[iVar1 + 8],0,3,in_r8,in_r9,in_r10);
  FUN_800303fc((double)*(float *)(&DAT_8031e980 +
                                 (uint)(byte)puVar3[(uint)*(byte *)(param_2 + 0x33a) * 0x10 + 8] * 4
                                 ),param_1);
  *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
  if ((byte)puVar3[8] < *(byte *)(param_2 + 0x33a)) {
    *(undefined *)(param_2 + 0x33a) = 1;
  }
  return;
}

